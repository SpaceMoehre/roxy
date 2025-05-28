use crate::http::httpresponse::HttpResponse;
use rustls::pki_types::pem::PemObject;
use rustls_pki_types::ServerName;
use ::time::OffsetDateTime;
use rcgen::DnValue::PrintableString;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time,
};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::{rustls::ServerConfig, TlsConnector};


fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let day = Duration::new(86400, 0);
    let yesterday = OffsetDateTime::now_utc() - day;
    let tomorrow = OffsetDateTime::now_utc() + day;
    (yesterday, tomorrow)
}

async fn generate_ca_cert() -> (CertificateParams, Certificate, KeyPair) {
    let mut params =
        CertificateParams::new(Vec::default()).expect("empty subject alt name can't produce error");
    let (yesterday, tomorrow) = validity_period();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(
        DnType::CountryName,
        PrintableString("BR".try_into().unwrap()),
    );
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Crab widgits SE");
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    params.not_before = yesterday;
    params.not_after = tomorrow;

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.clone().self_signed(&key_pair).unwrap();
    (params, cert, key_pair)
}

async fn generate_mitm_cert(
    ca: &CertificateParams,
    ca_cert: &Certificate,
    ca_key: &KeyPair,
    name: &str,
) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(vec![name.into()]).expect("we know the name is valid");
    let (yesterday, tomorrow) = validity_period();
    params.distinguished_name.push(DnType::CommonName, name);
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.not_before = yesterday;
    params.not_after = tomorrow;

    let key_pair = KeyPair::generate().unwrap();
    (
        params.signed_by(&key_pair, ca_cert, ca_key).unwrap(),
        key_pair,
    )
}

pub async fn handle_client(client_stream: &mut TcpStream) -> tokio::io::Result<()> {
    let mut buffer = vec![0; 8192];
    let n = client_stream.read(&mut buffer).await?;
    if n == 0 {
        return Ok(());
    }

    let request = &buffer[..n];

    if request.starts_with("CONNECT ".as_bytes()) {
        // Handle CONNECT method for HTTPS
        let request_str = String::from_utf8_lossy(request);
        let mut parts = request_str.split_whitespace();
        if let (Some(_method), Some(host_port), Some(version)) =
            (parts.next(), parts.next(), parts.next())
        {
            let mut host = host_port.to_string();
            println!("CONNECT request for host: {}", host);
            let response = format!("HTTP/1.1 200 Connection Established\r\n\r\n");
            client_stream.write_all(response.as_bytes()).await?;
            println!("Established connection to {}", host);

            let (ca_params, ca, ca_key) = generate_ca_cert().await;
            println!("Generated CA certificate");
            let (cert, keypair) = generate_mitm_cert(&ca_params, &ca, &ca_key, &host).await;
            println!("Generated MITM certificate for {}", host);
            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::try_from(keypair.serialize_der()).unwrap(),
                )
                .expect("Failed to create server config");
            let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

            let mut root_cert_store = rustls::RootCertStore::empty();

            root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            

            let config = rustls::ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth(); // i guess this was previously the default?
            let tls_connector = TlsConnector::from(Arc::new(config));
            let tls_client = tls_acceptor.accept(client_stream).await?;
            println!("TLS connection established with client");

            // // TLS connection to real server
            let remote_tcp = TcpStream::connect(host_port).await?;
            println!("Connected to remote server: {}", host_port);
            println!("Establishing TLS connection to remote server  {}", host.split(':').next().unwrap());
            let domain = ServerName::try_from(host.split(':').next().unwrap()).unwrap().to_owned();
            let tls_server = tls_connector.connect(domain, remote_tcp).await?;
            println!("TLS connection established with server");

            // Split the TLS streams into reader/writer halves
            let (mut client_reader, mut client_writer) = tokio::io::split(tls_client);
            let (mut server_reader, mut server_writer) = tokio::io::split(tls_server);

            // Forward client → server
            let client_to_server = async {
                let mut buf = [0u8; 4096];
                loop {
                    let n = client_reader.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    println!(
                        ">>> CLIENT → SERVER >>>\n{}",
                        String::from_utf8_lossy(&buf[..n])
                    );
                    server_writer.write_all(&buf[..n]).await?;
                }
                Ok::<_, tokio::io::Error>(())
            };

            // Forward server → client
            let server_to_client = async {
                let mut buf = [0u8; 4096];
                loop {
                    let n = server_reader.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    println!(
                        "<<< SERVER → CLIENT <<<\n{}",
                        String::from_utf8_lossy(&buf[..n])
                    );
                    client_writer.write_all(&buf[..n]).await?;
                }
                Ok::<_, tokio::io::Error>(())
            };

            // Run both directions concurrently
            tokio::try_join!(client_to_server, server_to_client)?;

            return Ok(());
        } else {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "Invalid CONNECT request",
            ));
        }
    }

    println!(">>> RAW REQUEST >>>\n{}", String::from_utf8_lossy(request));
    let corrected_request = correct_request_uri(request)?;
    println!(
        ">>> CORRECTED REQUEST >>>\n{}",
        String::from_utf8_lossy(&corrected_request)
    );
    // Parse host from the HTTP request
    let host = extract_host(&corrected_request)?;
    let addr = format!("{}:80", host);
    let mut server_stream = TcpStream::connect(addr.to_socket_addrs()?.next().unwrap()).await?;

    // Send request to the server
    server_stream.write_all(&corrected_request).await?;
    // Read response from the server
    let mut response = Vec::new();
    let mut temp = [0u8; 8192];
    let mut content_length: Option<usize> = None;
    let mut headers_parsed = false;
    let mut total_body_read = 0usize;

    loop {
        let n = server_stream.read(&mut temp).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&temp[..n]);

        if !headers_parsed {
            if let Some(headers_end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                headers_parsed = true;
                let header_bytes = &response[..headers_end + 4];
                if let Ok(resp) = HttpResponse::parse(header_bytes) {
                    if let Some(cl) = resp.get_header("Content-Length") {
                        if let Ok(cl_num) = cl.parse::<usize>() {
                            content_length = Some(cl_num);
                        }
                    }
                }
                total_body_read = response.len() - (headers_end + 4);
                if let Some(cl) = content_length {
                    if total_body_read >= cl {
                        break;
                    }
                }
            }
        } else if let Some(cl) = content_length {
            total_body_read += n;
            if total_body_read >= cl {
                break;
            }
        }
    }

    println!(
        "<<< RAW RESPONSE <<<\n{}",
        String::from_utf8_lossy(&response)
    );

    // Send response back to client
    client_stream.write_all(&response).await?;

    Ok(())
}

fn correct_request_uri(request: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let request_str = String::from_utf8_lossy(request);
    let mut lines = request_str.lines();
    if let Some(first_line) = lines.next() {
        let mut parts = first_line.split_whitespace();
        if let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next())
        {
            if let Ok(parsed_uri) = url::Url::parse(uri) {
                let mut path_and_query = parsed_uri.path().to_string();
                if let Some(query) = parsed_uri.query() {
                    path_and_query.push('?');
                    path_and_query.push_str(query);
                }
                let corrected_first_line = format!("{} {} {}", method, path_and_query, version);
                let mut corrected_request = corrected_first_line;
                for line in lines {
                    corrected_request.push_str("\r\n");
                    corrected_request.push_str(line);
                }
                corrected_request.push_str("\r\n");
                let corrected_bytes = corrected_request.into_bytes();
                return Ok(corrected_bytes);
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Failed to correct request URI",
    ))
}

fn extract_host(request: &[u8]) -> Result<String, std::io::Error> {
    let request_str = String::from_utf8_lossy(request);
    for line in request_str.lines() {
        if line.to_lowercase().starts_with("host:") {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() == 2 {
                return Ok(parts[1].trim().to_string());
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Host header not found",
    ))
}
