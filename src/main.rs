use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use std::{io::Write, net::ToSocketAddrs};
mod http;
use http::{HttpRequest, HttpResponse};

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Proxy listening on 127.0.0.1:8080");
    loop {
        let (mut client_stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(&mut client_stream).await {
                eprintln!("Error: {}", e);
            }
        });
    }
}

fn correct_request_uri(request: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let request_str = String::from_utf8_lossy(request);
    let mut lines = request_str.lines();
    if let Some(first_line) = lines.next() {
        let mut parts = first_line.split_whitespace();
        if let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next()) {
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

async fn handle_client(client_stream: &mut TcpStream) -> tokio::io::Result<()> {
    let mut buffer = vec![0; 8192];
    let n = client_stream.read(&mut buffer).await?;
    if n == 0 {
        return Ok(());
    }

    let request = &buffer[..n];
    println!(">>> RAW REQUEST >>>\n{}", String::from_utf8_lossy(request));
    let corrected_request = correct_request_uri(request)?;
    println!(
        ">>> CORRECTED REQUEST >>>\n{}",
        String::from_utf8_lossy(&corrected_request));
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
