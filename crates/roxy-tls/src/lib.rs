//! BoringSSL-based TLS helpers for both sides of the proxy.
//!
//! | Module | Role |
//! |---|---|
//! | [`client`] | Upstream TLS connector with post-quantum key exchange and brotli cert compression |
//! | [`server`] | Downstream MITM TLS acceptor built from per-domain leaf certs |
//! | [`ech`] | Encrypted Client Hello auto-discovery and retry logic |

pub mod client;
pub mod ech;
pub mod server;

pub use client::client_connector;
pub use ech::{EchRetry, apply_ech_client_config, ech_retry_from_handshake_error};
pub use server::build_downstream_mitm_acceptor;
