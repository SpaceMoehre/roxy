use tokio::
    net::TcpListener
;

mod http;
mod handler;
use handler::{handle_client};
mod ui;
use ui::start_webserver;

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    // Start the webserver in a separate thread
    std::thread::spawn(|| {
        if let Err(e) = start_webserver() {
            eprintln!("Webserver error: {}", e);
        }
    });

    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Proxy listening on 127.0.0.1:8080");

    // Create a shutdown signal future
    let shutdown_signal = async {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        println!("Received Ctrl+C, shutting down.");
    };

    tokio::select! {
        _ = async {
            loop {
                let (mut client_stream, _) = listener.accept().await?;
                tokio::spawn(async move {
                    if let Err(e) = handle_client(&mut client_stream).await {
                        eprintln!("Error: {}", e);
                    }
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