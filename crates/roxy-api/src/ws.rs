//! WebSocket broadcast hub for real-time event delivery.
//!
//! The [`WsHub`] fans out JSON-serialised events to every connected
//! browser tab.  Events originate from the proxy engine (new
//! exchanges), the intruder (job progress), and the plugin subsystem
//! (alterations).
//!
//! Two transport modes are supported:
//!
//! * **TCP** via [`run_ws_server`] and friends.
//! * **Unix domain socket** via
//!   [`run_ws_server_with_shutdown_and_ready_uds`].

use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU16, AtomicUsize, Ordering},
    },
};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::{broadcast, oneshot, watch},
};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{debug, info, warn};

/// Cheaply cloneable broadcast hub for WebSocket clients.
///
/// A single [`broadcast::Sender`]
/// distributes messages to all connected clients. An atomic counter
/// tracks the current number of live connections.
#[derive(Clone)]
pub struct WsHub {
    /// Fan-out channel carrying serialised JSON strings.
    tx: broadcast::Sender<String>,
    /// Live client count.
    clients: Arc<AtomicUsize>,
    /// Port the WS listener actually bound to (0 = not yet started).
    listen_port: Arc<AtomicU16>,
}

impl WsHub {
    /// Creates a new hub backed by a broadcast channel of the given
    /// `capacity`.
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            clients: Arc::new(AtomicUsize::new(0)),
            listen_port: Arc::new(AtomicU16::new(0)),
        }
    }

    /// Serialises `event` to JSON and broadcasts it to all connected
    /// WebSocket clients.
    pub fn publish<T: Serialize>(&self, event: &T) {
        if let Ok(payload) = serde_json::to_string(event) {
            let _ = self.tx.send(payload);
        }
    }

    /// Returns a new receiver for the raw JSON message stream.
    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    /// Returns the number of currently connected WebSocket clients.
    pub fn client_count(&self) -> usize {
        self.clients.load(Ordering::Relaxed)
    }

    /// Records the port the WebSocket listener actually bound to.
    pub fn set_listen_port(&self, port: u16) {
        self.listen_port.store(port, Ordering::Relaxed);
    }

    /// Returns the actual listen port, or `None` if the listener has
    /// not started yet.
    pub fn listen_port(&self) -> Option<u16> {
        let port = self.listen_port.load(Ordering::Relaxed);
        if port == 0 { None } else { Some(port) }
    }
}

/// Starts the WebSocket listener and blocks until the process is
/// terminated.
///
/// Convenience wrapper around [`run_ws_server_with_shutdown`].
///
/// # Errors
///
/// Returns an error if the TCP listener cannot be bound.
pub async fn run_ws_server(bind: SocketAddr, hub: WsHub) -> Result<()> {
    let (_tx, rx) = watch::channel(false);
    run_ws_server_with_shutdown(bind, hub, rx).await
}

/// Starts the listener and blocks until the `shutdown` channel
/// signals `true` or is dropped.
///
/// # Errors
///
/// Returns an error if the TCP listener cannot be bound.
pub async fn run_ws_server_with_shutdown(
    bind: SocketAddr,
    hub: WsHub,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    run_ws_server_with_shutdown_and_ready(bind, hub, shutdown, None).await
}

/// Starts the TCP listener with both a shutdown channel and an
/// optional `ready` oneshot that receives the actual bound
/// [`SocketAddr`].
///
/// If the requested port is busy the server will try incrementing
/// ports.
///
/// # Errors
///
/// Returns an error if no port can be bound.
pub async fn run_ws_server_with_shutdown_and_ready(
    bind: SocketAddr,
    hub: WsHub,
    mut shutdown: watch::Receiver<bool>,
    ready: Option<oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    let bind_addr = find_available_bind(bind)
        .await
        .with_context(|| format!("failed to find websocket bind from {bind}"))?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind websocket listener on {bind_addr}"))?;
    hub.set_listen_port(bind_addr.port());
    if let Some(tx) = ready {
        let _ = tx.send(bind_addr);
    }
    info!(requested_bind = %bind, actual_bind = %bind_addr, "websocket listener started");

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!("websocket listener shutdown requested");
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("ws accept failed")?;
                let hub = hub.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, hub).await {
                        debug!(%err, %peer, "websocket connection ended");
                    }
                });
            }
        }
    }

    Ok(())
}

/// Like [`run_ws_server_with_shutdown_and_ready`] but listens on a
/// Unix domain socket instead of TCP.
///
/// The socket file is cleaned up on shutdown.
///
/// # Errors
///
/// Returns an error if the UDS listener cannot be bound.
pub async fn run_ws_server_with_shutdown_and_ready_uds(
    path: impl AsRef<Path>,
    hub: WsHub,
    mut shutdown: watch::Receiver<bool>,
    ready: Option<oneshot::Sender<PathBuf>>,
) -> Result<()> {
    let path = path.as_ref().to_path_buf();
    cleanup_uds_socket_path(&path)?;

    let listener = tokio::net::UnixListener::bind(&path).with_context(|| {
        format!(
            "failed to bind websocket uds listener at {}",
            path.display()
        )
    })?;
    if let Some(tx) = ready {
        let _ = tx.send(path.clone());
    }
    info!(path = %path.display(), "websocket uds listener started");

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    info!(path = %path.display(), "websocket uds listener shutdown requested");
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _addr) = accepted.context("ws uds accept failed")?;
                let hub = hub.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, hub).await {
                        debug!(%err, "websocket uds connection ended");
                    }
                });
            }
        }
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}

async fn handle_connection<S>(stream: S, hub: WsHub) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws = accept_async(stream)
        .await
        .context("websocket handshake failed")?;
    hub.clients.fetch_add(1, Ordering::Relaxed);

    let (mut writer, mut reader) = ws.split();
    let mut rx = hub.subscribe();

    loop {
        tokio::select! {
            outbound = rx.recv() => {
                match outbound {
                    Ok(message) => {
                        if writer.send(Message::Text(message.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            inbound = reader.next() => {
                match inbound {
                    Some(Ok(Message::Ping(payload))) => {
                        if writer.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(err)) => {
                        warn!(%err, "websocket read error");
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    hub.clients.fetch_sub(1, Ordering::Relaxed);
    Ok(())
}

async fn find_available_bind(start: SocketAddr) -> io::Result<SocketAddr> {
    let mut addr = start;
    loop {
        match TcpListener::bind(addr).await {
            Ok(listener) => {
                drop(listener);
                return Ok(addr);
            }
            Err(err) if err.kind() == io::ErrorKind::AddrInUse => {
                addr = increment_port(addr)?;
            }
            Err(err) => return Err(err),
        }
    }
}

fn increment_port(mut addr: SocketAddr) -> io::Result<SocketAddr> {
    let port = addr.port();
    if port == u16::MAX {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "port range exhausted while searching for available bind",
        ));
    }
    addr.set_port(port + 1);
    Ok(addr)
}

fn cleanup_uds_socket_path(path: &Path) -> io::Result<()> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
