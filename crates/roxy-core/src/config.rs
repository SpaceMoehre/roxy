use std::{net::SocketAddr, time::Duration};

#[derive(Clone, Debug)]
pub struct DebugLoggingConfig {
    pub enabled: bool,
    pub log_bodies: bool,
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

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub bind: SocketAddr,
    pub request_timeout: Duration,
    pub mitm_enabled: bool,
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
