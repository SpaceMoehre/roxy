use tokio::
    net::TcpListener
;

mod http;
mod handler;
use handler::{handle_client};

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