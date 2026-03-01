use std::{
    net::TcpListener as StdTcpListener,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use reqwest::{Client, Proxy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::{sleep, timeout},
};

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local socket permissions in test environment"]
async fn proxy_intercept_and_history_flow() {
    let (upstream_addr, upstream_hits, upstream_shutdown, upstream_task) = start_upstream().await;

    let ingress_port = reserve_port();
    let data_dir = TempDir::new().expect("temp dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_roxy"));
    let plugin_dir = format!("{}/../../plugins", env!("CARGO_MANIFEST_DIR"));
    child
        .env("ROXY_BIND", format!("127.0.0.1:{ingress_port}"))
        .env("ROXY_PLUGIN_DIR", plugin_dir)
        .env("ROXY_DATA_DIR", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = child.spawn().expect("failed to spawn roxy");
    let _child_guard = ChildGuard::new(child);

    let api_base = format!("http://127.0.0.1:{ingress_port}/api/v1");
    let api_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("api client");
    wait_for_health(&api_client, &api_base, Duration::from_secs(15)).await;

    let toggle_response = api_client
        .put(format!("{api_base}/proxy/intercept"))
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .expect("toggle request intercept");
    assert!(toggle_response.status().is_success());

    let proxy_client = Client::builder()
        .proxy(Proxy::all(format!("http://127.0.0.1:{ingress_port}")).expect("proxy config"))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("proxy client");

    let target_url = format!("http://{upstream_addr}/hello?from=e2e");
    let request_task = tokio::spawn({
        let proxy_client = proxy_client.clone();
        let target_url = target_url.clone();
        async move {
            let response = proxy_client
                .get(target_url)
                .send()
                .await
                .expect("proxy request");
            let status = response.status();
            let body = response.text().await.expect("response body");
            (status.as_u16(), body)
        }
    });

    let intercept_id = wait_for_pending_intercept(&api_client, &api_base, Duration::from_secs(10))
        .await
        .expect("pending intercept id");

    assert_eq!(upstream_hits.load(Ordering::Relaxed), 0);

    let continue_response = api_client
        .post(format!(
            "{api_base}/proxy/intercepts/{intercept_id}/continue"
        ))
        .json(&json!({ "decision": "forward" }))
        .send()
        .await
        .expect("continue intercept");
    assert!(continue_response.status().is_success());

    let (status, body) = timeout(Duration::from_secs(10), request_task)
        .await
        .expect("request timed out")
        .expect("request join failed");
    assert_eq!(status, 200);
    assert_eq!(body, "upstream-ok");

    wait_for(Duration::from_secs(5), || async {
        upstream_hits.load(Ordering::Relaxed) == 1
    })
    .await;

    wait_for(Duration::from_secs(10), || {
        let api_client = api_client.clone();
        let api_base = api_base.clone();
        let target_url = target_url.clone();
        async move {
            let response = match api_client
                .get(format!("{api_base}/history/recent?limit=50"))
                .send()
                .await
            {
                Ok(row) => row,
                Err(_) => return false,
            };
            let payload: Value = match response.json().await {
                Ok(v) => v,
                Err(_) => return false,
            };
            payload.as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    row.get("exchange")
                        .and_then(|v| v.get("request"))
                        .and_then(|v| v.get("uri"))
                        .and_then(Value::as_str)
                        .is_some_and(|uri| uri == target_url)
                })
            })
        }
    })
    .await;

    let _ = upstream_shutdown.send(());
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local socket permissions in test environment"]
async fn single_port_ingress_routes_api_and_proxy() {
    let (upstream_addr, upstream_hits, upstream_shutdown, upstream_task) = start_upstream().await;

    let ingress_port = reserve_port();
    let data_dir = TempDir::new().expect("temp dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_roxy"));
    child
        .env("ROXY_BIND", format!("127.0.0.1:{ingress_port}"))
        .env("ROXY_DATA_DIR", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = child.spawn().expect("failed to spawn roxy");
    let _child_guard = ChildGuard::new(child);

    let api_base = format!("http://127.0.0.1:{ingress_port}/api/v1");
    let api_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("api client");
    wait_for_health(&api_client, &api_base, Duration::from_secs(15)).await;

    let proxy_client = Client::builder()
        .proxy(Proxy::all(format!("http://127.0.0.1:{ingress_port}")).expect("proxy config"))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("proxy client");

    let target_url = format!("http://{upstream_addr}/single-port");
    let response = proxy_client
        .get(target_url.clone())
        .send()
        .await
        .expect("proxy request");
    assert_eq!(response.status().as_u16(), 200);
    let body = response.text().await.expect("response body");
    assert_eq!(body, "upstream-ok");

    wait_for(Duration::from_secs(5), || async {
        upstream_hits.load(Ordering::Relaxed) == 1
    })
    .await;

    wait_for(Duration::from_secs(10), || {
        let api_client = api_client.clone();
        let api_base = api_base.clone();
        let target_url = target_url.clone();
        async move {
            let response = match api_client
                .get(format!("{api_base}/history/recent?limit=100"))
                .send()
                .await
            {
                Ok(row) => row,
                Err(_) => return false,
            };
            let payload: Value = match response.json().await {
                Ok(v) => v,
                Err(_) => return false,
            };

            payload.as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    row.get("exchange")
                        .and_then(|v| v.get("request"))
                        .and_then(|v| v.get("uri"))
                        .and_then(Value::as_str)
                        .is_some_and(|uri| uri == target_url)
                })
            })
        }
    })
    .await;

    let _ = upstream_shutdown.send(());
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local socket permissions and outbound internet access"]
async fn proxy_https_ifconfig_captured_in_roxy_api() {
    let ingress_port = reserve_port();
    let data_dir = TempDir::new().expect("temp dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_roxy"));
    child
        .env("ROXY_BIND", format!("127.0.0.1:{ingress_port}"))
        .env("ROXY_DATA_DIR", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = child.spawn().expect("failed to spawn roxy");
    let _child_guard = ChildGuard::new(child);

    let api_base = format!("http://127.0.0.1:{ingress_port}/api/v1");
    let api_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("api client");
    wait_for_health(&api_client, &api_base, Duration::from_secs(15)).await;

    let proxy_client = Client::builder()
        .proxy(Proxy::all(format!("http://127.0.0.1:{ingress_port}")).expect("proxy config"))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("proxy client");

    let response = timeout(
        Duration::from_secs(30),
        proxy_client
            .get("https://ifconfig.co/json")
            .header("user-agent", "roxy-e2e-test")
            .send(),
    )
    .await
    .expect("ifconfig request timed out")
    .expect("ifconfig request failed");
    assert!(
        response.status().is_success(),
        "unexpected status {}",
        response.status()
    );
    let _ = response.text().await.expect("read ifconfig response");

    wait_for(Duration::from_secs(20), || {
        let api_client = api_client.clone();
        let api_base = api_base.clone();
        async move {
            let response = match api_client
                .get(format!("{api_base}/history/recent?limit=200"))
                .send()
                .await
            {
                Ok(row) => row,
                Err(_) => return false,
            };
            let payload: Value = match response.json().await {
                Ok(v) => v,
                Err(_) => return false,
            };

            payload.as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    let uri = row
                        .get("exchange")
                        .and_then(|v| v.get("request"))
                        .and_then(|v| v.get("uri"))
                        .and_then(Value::as_str);
                    let status = row
                        .get("exchange")
                        .and_then(|v| v.get("response"))
                        .and_then(|v| v.get("status"))
                        .and_then(Value::as_u64);
                    let body = row
                        .get("exchange")
                        .and_then(|v| v.get("response"))
                        .and_then(|v| v.get("body"));

                    uri.is_some_and(|u| u.contains("ifconfig.co"))
                        && status.is_some_and(|s| (200..300).contains(&s))
                        && body_has_content(body)
                })
            })
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local socket permissions in test environment"]
async fn proxy_decodes_zstd_response_for_client_and_history() {
    let compressed_body =
        zstd::stream::encode_all("{\"ip\":\"1.2.3.4\"}".as_bytes(), 1).expect("encode zstd");
    let (upstream_addr, upstream_shutdown, upstream_task) = start_custom_upstream(
        200,
        vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Content-Encoding".to_string(), "zstd".to_string()),
        ],
        compressed_body,
    )
    .await;

    let ingress_port = reserve_port();
    let data_dir = TempDir::new().expect("temp dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_roxy"));
    child
        .env("ROXY_BIND", format!("127.0.0.1:{ingress_port}"))
        .env("ROXY_DATA_DIR", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = child.spawn().expect("failed to spawn roxy");
    let _child_guard = ChildGuard::new(child);

    let api_base = format!("http://127.0.0.1:{ingress_port}/api/v1");
    let api_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("api client");
    wait_for_health(&api_client, &api_base, Duration::from_secs(15)).await;

    let proxy_client = Client::builder()
        .proxy(Proxy::all(format!("http://127.0.0.1:{ingress_port}")).expect("proxy config"))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("proxy client");

    let target_url = format!("http://{upstream_addr}/compressed");
    let response = proxy_client
        .get(&target_url)
        .header("accept-encoding", "zstd")
        .send()
        .await
        .expect("proxy request");
    assert!(response.status().is_success());
    assert!(
        response.headers().get("content-encoding").is_none(),
        "proxy should strip content-encoding after decoding"
    );
    let client_body = response.text().await.expect("read client body");
    assert_eq!(client_body, r#"{"ip":"1.2.3.4"}"#);

    wait_for(Duration::from_secs(10), || {
        let api_client = api_client.clone();
        let api_base = api_base.clone();
        let target_url = target_url.clone();
        async move {
            let response = match api_client
                .get(format!("{api_base}/history/recent?limit=100"))
                .send()
                .await
            {
                Ok(row) => row,
                Err(_) => return false,
            };
            let payload: Value = match response.json().await {
                Ok(v) => v,
                Err(_) => return false,
            };

            payload.as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    let uri_matches = row
                        .get("exchange")
                        .and_then(|v| v.get("request"))
                        .and_then(|v| v.get("uri"))
                        .and_then(Value::as_str)
                        .is_some_and(|uri| uri == target_url);
                    if !uri_matches {
                        return false;
                    }

                    let response_headers = row
                        .get("exchange")
                        .and_then(|v| v.get("response"))
                        .and_then(|v| v.get("headers"))
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    let has_content_encoding = response_headers.iter().any(|h| {
                        h.get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|name| name.eq_ignore_ascii_case("content-encoding"))
                    });
                    if has_content_encoding {
                        return false;
                    }

                    let body_text = row
                        .get("exchange")
                        .and_then(|v| v.get("response"))
                        .and_then(|v| v.get("body"))
                        .and_then(decode_bytes_json_field);
                    body_text.as_deref() == Some(r#"{"ip":"1.2.3.4"}"#)
                })
            })
        }
    })
    .await;

    let _ = upstream_shutdown.send(());
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local socket permissions and python3 runtime in test environment"]
async fn plugin_middleware_substitutes_request_and_response_blobs() {
    let (upstream_addr, upstream_hits, upstream_shutdown, upstream_task) = start_upstream().await;

    let ingress_port = reserve_port();
    let data_dir = TempDir::new().expect("temp dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_roxy"));
    child
        .env("ROXY_BIND", format!("127.0.0.1:{ingress_port}"))
        .env("ROXY_DATA_DIR", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = child.spawn().expect("failed to spawn roxy");
    let _child_guard = ChildGuard::new(child);

    let api_base = format!("http://127.0.0.1:{ingress_port}/api/v1");
    let api_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("api client");
    wait_for_health(&api_client, &api_base, Duration::from_secs(15)).await;

    wait_for(Duration::from_secs(10), || {
        let api_client = api_client.clone();
        let api_base = api_base.clone();
        async move {
            let response = match api_client.get(format!("{api_base}/plugins")).send().await {
                Ok(row) => row,
                Err(_) => return false,
            };
            let payload: Value = match response.json().await {
                Ok(value) => value,
                Err(_) => return false,
            };
            payload.as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    row.get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|name| name == "string-substitute")
                })
            })
        }
    })
    .await;

    let index_html = api_client
        .get(format!("http://127.0.0.1:{ingress_port}/"))
        .send()
        .await
        .expect("fetch index")
        .text()
        .await
        .expect("index text");
    assert!(
        index_html.contains("setting-string-substitute-rule-count"),
        "expected string-substitute settings fields in settings tab"
    );

    let save_settings = api_client
        .put(format!("{api_base}/plugins/string-substitute/settings"))
        .json(&json!({
            "rules": [
                {
                    "scope": "request",
                    "search": "hello",
                    "replace": "alpha"
                },
                {
                    "scope": "response",
                    "search": "upstream-ok",
                    "replace": "omega"
                }
            ]
        }))
        .send()
        .await
        .expect("save plugin settings");
    assert!(save_settings.status().is_success());

    let proxy_client = Client::builder()
        .proxy(Proxy::all(format!("http://127.0.0.1:{ingress_port}")).expect("proxy config"))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("proxy client");

    let target_url = format!("http://{upstream_addr}/hello-world");
    let response = proxy_client
        .get(target_url)
        .send()
        .await
        .expect("proxy request");
    assert_eq!(response.status().as_u16(), 200);
    let body = response.text().await.expect("response text");
    assert_eq!(body, "omega");

    wait_for(Duration::from_secs(5), || async {
        upstream_hits.load(Ordering::Relaxed) == 1
    })
    .await;

    wait_for(Duration::from_secs(10), || {
        let api_client = api_client.clone();
        let api_base = api_base.clone();
        async move {
            let response = match api_client
                .get(format!("{api_base}/history/recent?limit=100"))
                .send()
                .await
            {
                Ok(row) => row,
                Err(_) => return false,
            };
            let payload: Value = match response.json().await {
                Ok(v) => v,
                Err(_) => return false,
            };

            payload.as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    let request_raw = row
                        .get("exchange")
                        .and_then(|v| v.get("request"))
                        .and_then(|v| v.get("raw"))
                        .and_then(decode_bytes_json_field);
                    let response_body = row
                        .get("exchange")
                        .and_then(|v| v.get("response"))
                        .and_then(|v| v.get("body"))
                        .and_then(decode_bytes_json_field);

                    request_raw
                        .as_deref()
                        .is_some_and(|blob| blob.contains("/alpha-world"))
                        && response_body.as_deref() == Some("omega")
                })
            })
        }
    })
    .await;

    let alterations = api_client
        .get(format!(
            "{api_base}/plugins/string-substitute/alterations?limit=20"
        ))
        .send()
        .await
        .expect("get plugin alterations")
        .json::<Value>()
        .await
        .expect("alterations json");
    assert!(
        alterations.as_array().is_some_and(|rows| {
            rows.iter()
                .any(|row| row.get("summary").and_then(Value::as_str).is_some())
        }),
        "expected alteration entries for string-substitute plugin"
    );

    let _ = upstream_shutdown.send(());
    let _ = upstream_task.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local socket permissions in test environment"]
async fn single_port_history_search_query_with_colon_is_accepted() {
    let ingress_port = reserve_port();
    let data_dir = TempDir::new().expect("temp dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_roxy"));
    child
        .env("ROXY_BIND", format!("127.0.0.1:{ingress_port}"))
        .env("ROXY_DATA_DIR", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = child.spawn().expect("failed to spawn roxy");
    let _child_guard = ChildGuard::new(child);

    let api_base = format!("http://127.0.0.1:{ingress_port}/api/v1");
    let api_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("api client");
    wait_for_health(&api_client, &api_base, Duration::from_secs(15)).await;

    let response = api_client
        .get(format!("{api_base}/history/search?q=a:b&limit=100"))
        .send()
        .await
        .expect("history search request");

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local socket permissions in test environment"]
async fn single_port_history_search_finds_colon_literal_from_response_blob() {
    let (upstream_addr, upstream_shutdown, upstream_task) = start_custom_upstream(
        200,
        vec![("Content-Type".to_string(), "application/json".to_string())],
        br#"{"marker":"bn:t"}"#.to_vec(),
    )
    .await;

    let ingress_port = reserve_port();
    let data_dir = TempDir::new().expect("temp dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_roxy"));
    child
        .env("ROXY_BIND", format!("127.0.0.1:{ingress_port}"))
        .env("ROXY_DATA_DIR", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = child.spawn().expect("failed to spawn roxy");
    let _child_guard = ChildGuard::new(child);

    let api_base = format!("http://127.0.0.1:{ingress_port}/api/v1");
    let api_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("api client");
    wait_for_health(&api_client, &api_base, Duration::from_secs(15)).await;

    let proxy_client = Client::builder()
        .proxy(Proxy::all(format!("http://127.0.0.1:{ingress_port}")).expect("proxy config"))
        .danger_accept_invalid_certs(true)
        .build()
        .expect("proxy client");

    let target_url = format!("http://{upstream_addr}/search-colon");
    let response = proxy_client
        .get(target_url.clone())
        .send()
        .await
        .expect("proxy request");
    assert!(response.status().is_success());
    let _ = response.text().await.expect("response body");

    wait_for(Duration::from_secs(10), || {
        let api_client = api_client.clone();
        let api_base = api_base.clone();
        let target_url = target_url.clone();
        async move {
            let response = match api_client
                .get(format!("{api_base}/history/search?q=bn:t&limit=100"))
                .send()
                .await
            {
                Ok(row) => row,
                Err(_) => return false,
            };
            if !response.status().is_success() {
                return false;
            }
            let payload: Value = match response.json().await {
                Ok(v) => v,
                Err(_) => return false,
            };
            payload.as_array().is_some_and(|rows| {
                rows.iter().any(|row| {
                    row.get("exchange")
                        .and_then(|v| v.get("request"))
                        .and_then(|v| v.get("uri"))
                        .and_then(Value::as_str)
                        .is_some_and(|uri| uri == target_url)
                })
            })
        }
    })
    .await;

    let _ = upstream_shutdown.send(());
    let _ = upstream_task.await;
}

fn reserve_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind local ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

async fn start_upstream() -> (
    std::net::SocketAddr,
    Arc<AtomicUsize>,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream listener");
    let addr = listener.local_addr().expect("upstream local addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = hits.clone();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else {
                        continue;
                    };
                    let hits_conn = hits_task.clone();
                    tokio::spawn(async move {
                        let mut buf = [0_u8; 2048];
                        let mut read = Vec::new();
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    read.extend_from_slice(&buf[..n]);
                                    if read.windows(4).any(|w| w == b"\r\n\r\n")
                                        || read.windows(2).any(|w| w == b"\n\n")
                                    {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }

                        hits_conn.fetch_add(1, Ordering::Relaxed);
                        let body = b"upstream-ok";
                        let headers = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(headers.as_bytes()).await;
                        let _ = stream.write_all(body).await;
                        let _ = stream.shutdown().await;
                    });
                }
            }
        }
    });

    (addr, hits, shutdown_tx, task)
}

async fn start_custom_upstream(
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind custom upstream listener");
    let addr = listener.local_addr().expect("upstream local addr");
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let body = Arc::new(body);
    let headers = Arc::new(headers);

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else {
                        continue;
                    };
                    let body = body.clone();
                    let headers = headers.clone();
                    tokio::spawn(async move {
                        let mut buf = [0_u8; 2048];
                        let mut read = Vec::new();
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) => break,
                                Ok(n) => {
                                    read.extend_from_slice(&buf[..n]);
                                    if read.windows(4).any(|w| w == b"\r\n\r\n")
                                        || read.windows(2).any(|w| w == b"\n\n")
                                    {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }

                        let mut response = format!("HTTP/1.1 {} OK\r\n", status);
                        for (k, v) in headers.iter() {
                            response.push_str(k);
                            response.push_str(": ");
                            response.push_str(v);
                            response.push_str("\r\n");
                        }
                        response.push_str(&format!("Content-Length: {}\r\n", body.len()));
                        response.push_str("Connection: close\r\n\r\n");
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.write_all(body.as_ref()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            }
        }
    });

    (addr, shutdown_tx, task)
}

async fn wait_for_health(client: &Client, api_base: &str, timeout_after: Duration) {
    wait_for(timeout_after, || {
        let client = client.clone();
        let api_base = api_base.to_string();
        async move {
            client
                .get(format!("{api_base}/health"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
        }
    })
    .await;
}

async fn wait_for_pending_intercept(
    client: &Client,
    api_base: &str,
    timeout_after: Duration,
) -> Option<String> {
    let started = Instant::now();
    while started.elapsed() < timeout_after {
        let response = match client
            .get(format!("{api_base}/proxy/intercepts"))
            .send()
            .await
        {
            Ok(row) => row,
            Err(_) => {
                sleep(Duration::from_millis(80)).await;
                continue;
            }
        };

        let payload: Value = match response.json().await {
            Ok(value) => value,
            Err(_) => {
                sleep(Duration::from_millis(80)).await;
                continue;
            }
        };

        if let Some(id) = payload
            .as_array()
            .and_then(|rows| rows.first())
            .and_then(|row| row.get("id"))
            .and_then(Value::as_str)
        {
            return Some(id.to_string());
        }

        sleep(Duration::from_millis(80)).await;
    }

    None
}

async fn wait_for<F, Fut>(timeout_after: Duration, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let started = Instant::now();
    while started.elapsed() < timeout_after {
        if condition().await {
            return;
        }
        sleep(Duration::from_millis(80)).await;
    }
    panic!("condition was not met within {:?}", timeout_after);
}

fn body_has_content(body: Option<&Value>) -> bool {
    let Some(body) = body else {
        return false;
    };
    if let Some(arr) = body.as_array() {
        return !arr.is_empty();
    }
    if let Some(s) = body.as_str() {
        return !s.is_empty();
    }
    false
}

fn decode_bytes_json_field(value: &Value) -> Option<String> {
    if let Some(s) = value.as_str() {
        return Some(s.to_string());
    }

    let arr = value.as_array()?;
    let bytes: Vec<u8> = arr
        .iter()
        .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect::<Option<Vec<_>>>()?;
    Some(String::from_utf8_lossy(&bytes).to_string())
}
