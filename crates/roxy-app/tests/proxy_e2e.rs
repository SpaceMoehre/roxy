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

    let proxy_port = reserve_port();
    let api_port = reserve_port();
    let ws_port = reserve_port();
    let data_dir = TempDir::new().expect("temp dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_roxy-app"));
    child
        .env("ROXY_PROXY_BIND", format!("127.0.0.1:{proxy_port}"))
        .env("ROXY_API_BIND", format!("127.0.0.1:{api_port}"))
        .env("ROXY_WS_BIND", format!("127.0.0.1:{ws_port}"))
        .env("ROXY_DATA_DIR", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = child.spawn().expect("failed to spawn roxy-app");
    let _child_guard = ChildGuard::new(child);

    let api_base = format!("http://127.0.0.1:{api_port}/api/v1");
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
        .proxy(Proxy::all(format!("http://127.0.0.1:{proxy_port}")).expect("proxy config"))
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
#[ignore = "requires local socket permissions and outbound internet access"]
async fn proxy_https_ifconfig_captured_in_roxy_api() {
    let proxy_port = reserve_port();
    let api_port = reserve_port();
    let ws_port = reserve_port();
    let data_dir = TempDir::new().expect("temp dir");

    let mut child = Command::new(env!("CARGO_BIN_EXE_roxy-app"));
    child
        .env("ROXY_PROXY_BIND", format!("127.0.0.1:{proxy_port}"))
        .env("ROXY_API_BIND", format!("127.0.0.1:{api_port}"))
        .env("ROXY_WS_BIND", format!("127.0.0.1:{ws_port}"))
        .env("ROXY_DATA_DIR", data_dir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = child.spawn().expect("failed to spawn roxy-app");
    let _child_guard = ChildGuard::new(child);

    let api_base = format!("http://127.0.0.1:{api_port}/api/v1");
    let api_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("api client");
    wait_for_health(&api_client, &api_base, Duration::from_secs(15)).await;

    let proxy_client = Client::builder()
        .proxy(Proxy::all(format!("http://127.0.0.1:{proxy_port}")).expect("proxy config"))
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
