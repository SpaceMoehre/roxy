use std::{net::SocketAddr, time::Duration};

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub bind: SocketAddr,
    pub request_timeout: Duration,
    pub mitm_enabled: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:8080".parse().expect("valid default proxy bind"),
            request_timeout: Duration::from_secs(30),
            mitm_enabled: true,
        }
    }
}
