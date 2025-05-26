use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use std::net::ToSocketAddrs;
mod http;
use http::HttpRequest;

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

fn correct_request_uri(request: &mut [u8]) -> Result<(), std::io::Error> {
    let request_str = String::from_utf8_lossy(request);
    let mut lines = request_str.lines();
    if let Some(first_line) = lines.next() {
        let mut parts = first_line.split_whitespace();
        if let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next()) {
            if let Ok(parsed_uri) = url::Url::parse(uri) {
                if let Some(path) = parsed_uri.path_and_query() {
                    let corrected_first_line = format!("{} {} {}", method, path, version);
                    let mut corrected_request = corrected_first_line;
                    for line in lines {
                        corrected_request.push_str("\r\n");
                        corrected_request.push_str(line);
                    }
                    corrected_request.push_str("\r\n\r\n");
                    request[..corrected_request.len()].copy_from_slice(corrected_request.as_bytes());
                    return Ok(());
                }
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

    let mut request = &buffer[..n];
    println!(">>> RAW REQUEST >>>\n{}", String::from_utf8_lossy(request));
    correct_request_uri(&mut request)?;
    println!(
        ">>> CORRECTED REQUEST >>>\n{}",
        String::from_utf8_lossy(&request[..n])
    );
    // Parse host from the HTTP request
    let host = extract_host(request)?;
    let addr = format!("{}:80", host);
    let mut server_stream = TcpStream::connect(addr.to_socket_addrs()?.next().unwrap()).await?;
    let mut http_request = HttpRequest::parse(request).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Failed to parse request: {}", e))
    })?;
    match http_request.replace_proxy_uri(){
        Ok(_) => {}
        Err(e) => {
            eprintln!("Error replacing proxy URI: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e));
        }
    }
    

    println!("Parsed HTTP request: {:?}", http_request);
    // Send request to the server
    server_stream.write_all(request).await?;

    // Read response from the server
    let mut response = Vec::new();
    let mut temp = [0u8; 8192];

    loop {
        let n = server_stream.read(&mut temp).await?;
        if n == 0 {
            break;
        }
        response.extend_from_slice(&temp[..n]);
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
