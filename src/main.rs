use std::sync::{Arc};
use tokio::sync::Mutex;
use tokio::net::TcpListener;
use once_cell::sync::Lazy;
mod handler;
mod http;
use handler::handle_client;
mod ui;
use ui::start_webserver;
use util::cert::CertificateManager;
mod util;


pub static CERT_MANAGER: Lazy<Arc<Mutex<CertificateManager>>> =
    Lazy::new(|| Arc::new(Mutex::new(CertificateManager::new())));

#[tokio::main]
async fn main() -> tokio::io::Result<()> {

    // Start the webserver in a separate thread
    std::thread::spawn(|| {
        if let Err(e) = start_webserver() {
            eprintln!("Webserver error: {}", e);
        }
    });

    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    println!("Proxy listening on 0.0.0.0:8080");

    // Create a shutdown signal future
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for ctrl+c");
        println!("Received Ctrl+C, shutting down.");
    };

    tokio::select! {
        _ = async {
            loop {
                println!("Waiting for client connection...");
                let (mut client_stream, _) = listener.accept().await?;
                tokio::spawn(async move {
                    if let Err(e) = handle_client(&mut client_stream).await {
                        eprintln!("Error: {}", e);
                    }
                    println!("Client connection closed.");
                });
            }
            #[allow(unreachable_code)]
            Ok::<(), tokio::io::Error>(())
        } => {},
        _ = shutdown_signal => {
            // Optionally: perform cleanup here
            println!("Shutting down gracefully...");
            return Ok(());
        }
    }

    Ok(())
}
