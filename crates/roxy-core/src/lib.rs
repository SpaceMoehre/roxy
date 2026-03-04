//! Core engine for the **roxy** intercepting proxy.
//!
//! `roxy-core` contains every runtime primitive that the proxy needs:
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`cert`] | TLS CA generation and per-domain MITM leaf certificates |
//! | [`config`] | Proxy bind address, timeouts, and debug-logging knobs |
//! | [`intruder`] | HTTP fuzzer with Sniper / ClusterBomb attack strategies |
//! | [`middleware`] | Async trait hook for plugin-injected request/response transforms |
//! | [`model`] | Shared domain types: captured requests, responses, exchanges |
//! | [`outbound`] | Shared HTTP client used by the repeater and intruder |
//! | [`proxy`] | The main proxy engine — HTTP forwarding, HTTPS CONNECT, MITM |
//! | [`raw_http`] | Raw HTTP blob parser / builder for lossless request editing |
//! | [`state`] | Central mutable state: intercept queues, scope, site-map, upstream proxies |
//!
//! All public types are re-exported at the crate root for convenience.

pub mod cert;
pub mod config;
pub mod intruder;
pub mod middleware;
pub mod model;
pub mod outbound;
pub mod proxy;
pub mod raw_http;
pub mod state;

pub use cert::{CaCertificate, CertManager, DomainCertificate};
pub use config::{DebugLoggingConfig, ProxyConfig};
pub use intruder::{
    IntruderEvent, IntruderJobDetails, IntruderJobSnapshot, IntruderJobSpec, IntruderJobStatus,
    IntruderManager, IntruderPayloadSet, IntruderResult, IntruderStrategy,
};
pub use middleware::ProxyMiddleware;
pub use model::{
    CapturedExchange, CapturedRequest, CapturedResponse, EventEnvelope, HeaderValuePair,
    RequestMutation, ResponseMutation,
};
pub use outbound::{OutboundResponse, send_parsed_request};
pub use proxy::ProxyEngine;
pub use raw_http::{ParsedRequestBlob, build_request_blob, parse_request_blob};
pub use state::{
    AppState, AppStateEvent, InterceptDecision, PendingInterceptSnapshot, ProxyToggleSnapshot,
    ResponseInterceptDecision, ScopeSnapshot, SiteMapEntry, SiteMapSnapshot, StateError,
    UpstreamChainMode, UpstreamProxyEntry, UpstreamProxyProtocol, UpstreamProxySettings,
};
