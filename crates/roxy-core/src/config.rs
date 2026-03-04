//! Proxy server configuration types.
//!
//! This module provides the [`ProxyConfig`] struct that the [`ProxyEngine`](crate::proxy::ProxyEngine)
//! consumes at construction time, together with the nested [`DebugLoggingConfig`] that
//! controls verbose request/response tracing at runtime.
//!
//! Both types implement [`Default`] with production-ready values so callers need
//! only override the fields they care about.

use std::{net::SocketAddr, time::Duration};

/// Controls the verbosity of per-request debug logging emitted by the proxy
/// engine.
///
/// When [`enabled`](Self::enabled) is `true` the engine logs structured
/// `tracing` spans for every request/response snapshot. Setting
/// [`log_bodies`](Self::log_bodies) additionally prints a UTF-8 preview of the
/// body bytes, capped at [`body_preview_bytes`](Self::body_preview_bytes).
///
/// # Defaults
///
/// | Field | Value |
/// |-------|-------|
/// | `enabled` | `false` |
/// | `log_bodies` | `false` |
/// | `body_preview_bytes` | `2048` |
#[derive(Clone, Debug)]
pub struct DebugLoggingConfig {
    /// Master switch — when `false`, no per-request debug spans are emitted.
    pub enabled: bool,
    /// Whether to include a UTF-8 body preview in request/response snapshots.
    pub log_bodies: bool,
    /// Maximum number of body bytes to include in each preview line.
    pub body_preview_bytes: usize,
}

impl Default for DebugLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_bodies: false,
            body_preview_bytes: 2048,
        }
    }
}

/// Top-level configuration for the [`ProxyEngine`](crate::proxy::ProxyEngine).
///
/// # Defaults
///
/// | Field | Value |
/// |-------|-------|
/// | `bind` | `127.0.0.1:8080` |
/// | `request_timeout` | 30 s |
/// | `mitm_enabled` | `true` |
/// | `debug_logging` | all off (see [`DebugLoggingConfig::default`]) |
///
/// # Panics
///
/// The [`Default`] impl calls [`str::parse`] on a hard-coded socket address
/// and will panic only if the literal is invalid (which is impossible with the
/// current value).
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Local address the proxy engine listens on.
    pub bind: SocketAddr,
    /// Maximum wall-clock time allowed for a single upstream round-trip.
    pub request_timeout: Duration,
    /// When `true`, HTTPS CONNECT tunnels are intercepted with a per-domain
    /// leaf certificate and the traffic is captured.  When `false`, CONNECT
    /// tunnels are passed through opaquely.
    pub mitm_enabled: bool,
    /// Debug logging knobs — see [`DebugLoggingConfig`].
    pub debug_logging: DebugLoggingConfig,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".parse().expect("valid default proxy bind"),
            request_timeout: Duration::from_secs(30),
            mitm_enabled: true,
            debug_logging: DebugLoggingConfig::default(),
        }
    }
}
