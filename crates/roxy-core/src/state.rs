//! Central shared proxy state.
//!
//! [`AppState`] is the single source of truth for every runtime toggle and
//! queue that the proxy engine, the API layer, and the WebSocket hub need to
//! coordinate on:
//!
//! * **Intercept toggles** — enable/disable request and response interception
//!   and MITM mode.
//! * **Pending intercept queues** — requests and responses waiting for user
//!   decisions (forward / mutate / drop), backed by
//!   [`oneshot`] channels.
//! * **Site map** — accumulated host + path tree built while traffic flows
//!   through the proxy, filtered by scope.
//! * **Scope** — a set of host patterns (optionally wildcard-prefixed, e.g.
//!   `*.example.com`) that restrict which hosts enter the site map.
//! * **Upstream proxy settings** — optional proxy chain configuration
//!   (HTTP / HTTPS / SOCKS4 / SOCKS5, strict-chain / random-chain).
//!
//! Every mutation publishes an [`AppStateEvent`] through a
//! [`broadcast`] channel so the WebSocket hub can
//! push real-time updates to the dashboard.

use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
};

use dashmap::{DashMap, DashSet};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, oneshot};
use uuid::Uuid;

use crate::model::{CapturedRequest, CapturedResponse, RequestMutation, ResponseMutation};

/// The proxy engine's decision for an intercepted request.
#[derive(Debug)]
pub enum InterceptDecision {
    /// Pass the request through to the upstream server unchanged.
    Forward,
    /// Replace the request's raw blob before forwarding.
    Mutate(RequestMutation),
    /// Discard the request entirely; the client receives a `403 Forbidden`.
    Drop,
}

/// The proxy engine's decision for an intercepted response.
#[derive(Debug)]
pub enum ResponseInterceptDecision {
    /// Deliver the response to the client unchanged.
    Forward,
    /// Replace status / headers / body before delivery.
    Mutate(ResponseMutation),
    /// Discard the response; the client receives a `403 Forbidden`.
    Drop,
}

/// Transport protocol for an upstream proxy hop.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProxyProtocol {
    /// Plain-text HTTP CONNECT tunnel.
    Http,
    /// TLS-wrapped HTTP CONNECT tunnel.
    Https,
    /// SOCKS4/4a tunnel.
    Socks4,
    /// SOCKS5 tunnel (no-auth only).
    Socks5,
}

/// A single hop in the upstream proxy chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamProxyEntry {
    /// Transport protocol for this hop.
    pub protocol: UpstreamProxyProtocol,
    /// Hostname or IP address of the proxy.
    pub address: String,
    /// TCP port of the proxy.
    pub port: u16,
}

/// How to select hops from the configured proxy list.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamChainMode {
    /// Use every proxy in order.
    StrictChain,
    /// Randomly select and shuffle a subset of proxies per connection, bounded
    /// by [`UpstreamProxySettings::min_chain_length`] and
    /// [`UpstreamProxySettings::max_chain_length`].
    RandomChain,
}

/// Complete configuration for upstream proxy chaining.
///
/// Implements [`Default`] with an empty proxy list and strict-chain mode.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UpstreamProxySettings {
    /// Ordered list of proxy hops.
    pub proxies: Vec<UpstreamProxyEntry>,
    /// When `true`, DNS resolution is delegated to the first proxy in the
    /// chain rather than being resolved locally.
    pub proxy_dns: bool,
    /// Chain selection strategy.
    pub chain_mode: UpstreamChainMode,
    /// Minimum number of hops in random-chain mode (clamped to ≥ 1).
    pub min_chain_length: usize,
    /// Maximum number of hops in random-chain mode (clamped to ≥ `min`).
    pub max_chain_length: usize,
}

/// Snapshot of the three proxy toggle switches (request intercept, response
/// intercept, MITM).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyToggleSnapshot {
    /// Whether request interception is currently active.
    pub intercept_enabled: bool,
    /// Whether response interception is currently active.
    pub intercept_response_enabled: bool,
    /// Whether HTTPS CONNECT tunnels are intercepted (MITM mode).
    pub mitm_enabled: bool,
}

/// Snapshot of all queued intercept requests and responses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingInterceptSnapshot {
    /// Requests waiting for a user decision.
    pub requests: Vec<CapturedRequest>,
    /// Responses waiting for a user decision.
    pub responses: Vec<CapturedResponse>,
}

/// One row in the site map — a host and its observed paths.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SiteMapEntry {
    /// Hostname (lowercased).
    pub host: String,
    /// Sorted list of unique request paths seen for this host.
    pub paths: Vec<String>,
}

/// Complete site map snapshot, ordered by host name.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SiteMapSnapshot {
    /// Sorted list of host → paths entries.
    pub rows: Vec<SiteMapEntry>,
}

/// Snapshot of the current scope host patterns.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScopeSnapshot {
    /// Sorted list of scope host patterns (e.g. `["*.example.com"]`).
    pub hosts: Vec<String>,
}

/// Event broadcast by [`AppState`] whenever a toggle, queue, site map, scope,
/// or upstream proxy setting changes.
///
/// Tagged serde representation: `{"event": "<variant>", "payload": {…}}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", content = "payload", rename_all = "snake_case")]
pub enum AppStateEvent {
    /// One or more proxy toggles changed.
    ProxyToggles(ProxyToggleSnapshot),
    /// The set of pending intercept requests/responses changed.
    PendingIntercepts(PendingInterceptSnapshot),
    /// A new host or path was added to the site map.
    SiteMapUpdated(SiteMapSnapshot),
    /// The scope host list was modified.
    ScopeUpdated(ScopeSnapshot),
    /// Upstream proxy chain settings were updated.
    UpstreamProxySettingsUpdated(UpstreamProxySettings),
}

impl Default for UpstreamProxySettings {
    fn default() -> Self {
        Self {
            proxies: Vec::new(),
            proxy_dns: false,
            chain_mode: UpstreamChainMode::StrictChain,
            min_chain_length: 1,
            max_chain_length: 1,
        }
    }
}

impl UpstreamProxySettings {
    /// Returns a sanitised copy with empty/zero entries removed and chain
    /// length bounds clamped to sensible minimums.
    pub fn normalized(mut self) -> Self {
        self.proxies = self
            .proxies
            .into_iter()
            .filter_map(|mut proxy| {
                proxy.address = proxy.address.trim().to_string();
                if proxy.address.is_empty() || proxy.port == 0 {
                    return None;
                }
                Some(proxy)
            })
            .collect();
        self.min_chain_length = self.min_chain_length.max(1);
        self.max_chain_length = self.max_chain_length.max(1).max(self.min_chain_length);
        self
    }
}

/// A request that is parked in the intercept queue waiting for a user
/// decision.
///
/// Created by [`AppState::enqueue_intercept`] and resolved by
/// [`AppState::continue_intercept`].
#[derive(Debug)]
pub struct PendingIntercept {
    /// The captured request awaiting a decision.
    pub request: CapturedRequest,
    /// One-shot channel used to deliver the [`InterceptDecision`].
    sender: Mutex<Option<oneshot::Sender<InterceptDecision>>>,
}

impl PendingIntercept {
    /// Creates a new pending intercept and returns the `Arc`-wrapped handle
    /// together with the receiver the proxy engine awaits on.
    pub fn new(request: CapturedRequest) -> (Arc<Self>, oneshot::Receiver<InterceptDecision>) {
        let (tx, rx) = oneshot::channel();
        (
            Arc::new(Self {
                request,
                sender: Mutex::new(Some(tx)),
            }),
            rx,
        )
    }

    fn resolve(&self, decision: InterceptDecision) -> Result<(), StateError> {
        let tx = self
            .sender
            .lock()
            .map_err(|_| StateError::InternalLock)?
            .take()
            .ok_or(StateError::AlreadyResolved)?;

        tx.send(decision).map_err(|_| StateError::ReceiverDropped)
    }
}

/// A response that is parked in the intercept queue waiting for a user
/// decision.
///
/// Created by [`AppState::enqueue_response_intercept`] and resolved by
/// [`AppState::continue_response_intercept`].
#[derive(Debug)]
pub struct PendingResponseIntercept {
    /// The captured response awaiting a decision.
    pub response: CapturedResponse,
    /// One-shot channel used to deliver the [`ResponseInterceptDecision`].
    sender: Mutex<Option<oneshot::Sender<ResponseInterceptDecision>>>,
}

impl PendingResponseIntercept {
    /// Creates a new pending response intercept and returns the `Arc`-wrapped
    /// handle together with the receiver.
    pub fn new(
        response: CapturedResponse,
    ) -> (Arc<Self>, oneshot::Receiver<ResponseInterceptDecision>) {
        let (tx, rx) = oneshot::channel();
        (
            Arc::new(Self {
                response,
                sender: Mutex::new(Some(tx)),
            }),
            rx,
        )
    }

    fn resolve(&self, decision: ResponseInterceptDecision) -> Result<(), StateError> {
        let tx = self
            .sender
            .lock()
            .map_err(|_| StateError::InternalLock)?
            .take()
            .ok_or(StateError::AlreadyResolved)?;

        tx.send(decision).map_err(|_| StateError::ReceiverDropped)
    }
}

/// Errors returned by intercept queue operations.
#[derive(Debug, Error)]
pub enum StateError {
    #[error("request not found in intercept queue")]
    NotFound,
    #[error("request already resolved")]
    AlreadyResolved,
    #[error("receiver is dropped")]
    ReceiverDropped,
    #[error("internal state lock failure")]
    InternalLock,
}

/// Central mutable state shared by the proxy engine, API layer, and
/// WebSocket hub.
///
/// All fields are lock-free or use fine-grained interior mutability so
/// concurrent access from many tasks does not become a bottleneck.
#[derive(Debug)]
pub struct AppState {
    intercept_enabled: AtomicBool,
    intercept_response_enabled: AtomicBool,
    mitm_enabled: AtomicBool,
    pending_intercepts: DashMap<Uuid, Arc<PendingIntercept>>,
    pending_response_intercepts: DashMap<Uuid, Arc<PendingResponseIntercept>>,
    site_map: DashMap<String, DashSet<String>>,
    scope_hosts: DashSet<String>,
    upstream_proxy_settings: RwLock<UpstreamProxySettings>,
    events_tx: broadcast::Sender<AppStateEvent>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    /// Creates a fresh `AppState` with interception disabled, MITM enabled,
    /// empty site map, empty scope, and default upstream proxy settings.
    pub fn new() -> Self {
        let (events_tx, _) = broadcast::channel(2048);
        Self {
            intercept_enabled: AtomicBool::new(false),
            intercept_response_enabled: AtomicBool::new(false),
            mitm_enabled: AtomicBool::new(true),
            pending_intercepts: DashMap::new(),
            pending_response_intercepts: DashMap::new(),
            site_map: DashMap::new(),
            scope_hosts: DashSet::new(),
            upstream_proxy_settings: RwLock::new(UpstreamProxySettings::default()),
            events_tx,
        }
    }

    /// Returns a new [`broadcast::Receiver`] that will receive every
    /// [`AppStateEvent`] published after the subscription is created.
    pub fn subscribe_events(&self) -> broadcast::Receiver<AppStateEvent> {
        self.events_tx.subscribe()
    }

    fn publish_event(&self, event: AppStateEvent) {
        let _ = self.events_tx.send(event);
    }

    fn proxy_toggle_snapshot(&self) -> ProxyToggleSnapshot {
        ProxyToggleSnapshot {
            intercept_enabled: self.intercept_enabled(),
            intercept_response_enabled: self.intercept_response_enabled(),
            mitm_enabled: self.mitm_enabled(),
        }
    }

    fn pending_intercepts_snapshot(&self) -> PendingInterceptSnapshot {
        PendingInterceptSnapshot {
            requests: self.pending_requests(),
            responses: self.pending_responses(),
        }
    }

    fn site_map_snapshot(&self) -> SiteMapSnapshot {
        SiteMapSnapshot {
            rows: self
                .site_map()
                .into_iter()
                .map(|(host, paths)| SiteMapEntry { host, paths })
                .collect(),
        }
    }

    fn scope_snapshot(&self) -> ScopeSnapshot {
        ScopeSnapshot {
            hosts: self.scope_hosts(),
        }
    }

    /// Returns `true` when request interception is active.
    pub fn intercept_enabled(&self) -> bool {
        self.intercept_enabled.load(Ordering::Relaxed)
    }

    /// Enables or disables request interception.
    ///
    /// When disabled, all currently pending intercepts are automatically
    /// flushed with [`InterceptDecision::Forward`].
    pub fn set_intercept_enabled(&self, enabled: bool) {
        self.intercept_enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            self.flush_pending_intercepts_forward();
        }
        self.publish_event(AppStateEvent::ProxyToggles(self.proxy_toggle_snapshot()));
        self.publish_event(AppStateEvent::PendingIntercepts(
            self.pending_intercepts_snapshot(),
        ));
    }

    /// Returns `true` when response interception is active.
    pub fn intercept_response_enabled(&self) -> bool {
        self.intercept_response_enabled.load(Ordering::Relaxed)
    }

    /// Enables or disables response interception.
    pub fn set_intercept_response_enabled(&self, enabled: bool) {
        self.intercept_response_enabled
            .store(enabled, Ordering::Relaxed);
        self.publish_event(AppStateEvent::ProxyToggles(self.proxy_toggle_snapshot()));
    }

    /// Returns `true` when HTTPS CONNECT tunnels are intercepted (MITM mode).
    pub fn mitm_enabled(&self) -> bool {
        self.mitm_enabled.load(Ordering::Relaxed)
    }

    /// Enables or disables MITM interception for HTTPS CONNECT tunnels.
    pub fn set_mitm_enabled(&self, enabled: bool) {
        self.mitm_enabled.store(enabled, Ordering::Relaxed);
        self.publish_event(AppStateEvent::ProxyToggles(self.proxy_toggle_snapshot()));
    }

    /// Parks `request` in the pending intercept queue and returns a
    /// [`oneshot::Receiver`] that the proxy engine awaits to learn the user's
    /// decision.
    pub fn enqueue_intercept(
        &self,
        request: CapturedRequest,
    ) -> oneshot::Receiver<InterceptDecision> {
        let id = request.id;
        let (pending, rx) = PendingIntercept::new(request);
        self.pending_intercepts.insert(id, pending);
        self.publish_event(AppStateEvent::PendingIntercepts(
            self.pending_intercepts_snapshot(),
        ));
        rx
    }

    /// Resolves a pending request intercept with the given `decision`.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::NotFound`] if `id` is not in the queue, or
    /// [`StateError::AlreadyResolved`] if it was already resolved.
    pub fn continue_intercept(
        &self,
        id: Uuid,
        decision: InterceptDecision,
    ) -> Result<(), StateError> {
        let entry = self
            .pending_intercepts
            .remove(&id)
            .ok_or(StateError::NotFound)?;
        let result = entry.1.resolve(decision);
        self.publish_event(AppStateEvent::PendingIntercepts(
            self.pending_intercepts_snapshot(),
        ));
        result
    }

    /// Returns a snapshot of all currently queued request intercepts, sorted
    /// by creation timestamp.
    pub fn pending_requests(&self) -> Vec<CapturedRequest> {
        let mut rows: Vec<CapturedRequest> = self
            .pending_intercepts
            .iter()
            .map(|entry| entry.value().request.clone())
            .collect();
        rows.sort_by_key(|r| r.created_at_unix_ms);
        rows
    }

    fn flush_pending_intercepts_forward(&self) {
        let ids: Vec<Uuid> = self
            .pending_intercepts
            .iter()
            .map(|entry| *entry.key())
            .collect();
        for id in ids {
            if let Some((_, pending)) = self.pending_intercepts.remove(&id) {
                let _ = pending.resolve(InterceptDecision::Forward);
            }
        }
        self.publish_event(AppStateEvent::PendingIntercepts(
            self.pending_intercepts_snapshot(),
        ));
    }

    /// Parks `response` in the pending response intercept queue and returns
    /// a receiver for the user's decision.
    pub fn enqueue_response_intercept(
        &self,
        response: CapturedResponse,
    ) -> oneshot::Receiver<ResponseInterceptDecision> {
        let id = response.request_id;
        let (pending, rx) = PendingResponseIntercept::new(response);
        self.pending_response_intercepts.insert(id, pending);
        self.publish_event(AppStateEvent::PendingIntercepts(
            self.pending_intercepts_snapshot(),
        ));
        rx
    }

    /// Resolves a pending response intercept with the given `decision`.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::NotFound`] if `id` is not in the queue.
    pub fn continue_response_intercept(
        &self,
        id: Uuid,
        decision: ResponseInterceptDecision,
    ) -> Result<(), StateError> {
        let entry = self
            .pending_response_intercepts
            .remove(&id)
            .ok_or(StateError::NotFound)?;
        let result = entry.1.resolve(decision);
        self.publish_event(AppStateEvent::PendingIntercepts(
            self.pending_intercepts_snapshot(),
        ));
        result
    }

    /// Returns a snapshot of all currently queued response intercepts, sorted
    /// by creation timestamp.
    pub fn pending_responses(&self) -> Vec<CapturedResponse> {
        let mut rows: Vec<CapturedResponse> = self
            .pending_response_intercepts
            .iter()
            .map(|entry| entry.value().response.clone())
            .collect();
        rows.sort_by_key(|r| r.created_at_unix_ms);
        rows
    }

    /// Records a `(host, path)` pair in the site map.
    ///
    /// The host is lowercased and checked against the current scope; if out
    /// of scope the call is a no-op.  Duplicate paths are silently ignored.
    pub fn register_site_path(&self, host: impl Into<String>, path: impl Into<String>) {
        let host = host.into().trim().to_ascii_lowercase();
        if !self.host_in_scope(&host) {
            return;
        }
        let path = path.into();
        let inserted = self.site_map.entry(host).or_default().insert(path);
        if inserted {
            self.publish_event(AppStateEvent::SiteMapUpdated(self.site_map_snapshot()));
        }
    }

    /// Returns the full site map as a sorted `Vec` of `(host, paths)` pairs.
    pub fn site_map(&self) -> Vec<(String, Vec<String>)> {
        let mut out = Vec::new();
        for host in &self.site_map {
            let mut paths: Vec<String> = host.value().iter().map(|p| p.clone()).collect();
            paths.sort();
            out.push((host.key().clone(), paths));
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Replaces the entire scope host list.
    ///
    /// Each entry is lowercased; empty strings are discarded.  Wildcard
    /// patterns like `*.example.com` match the domain itself and all
    /// sub-domains.
    pub fn set_scope_hosts(&self, hosts: Vec<String>) {
        self.scope_hosts.clear();
        for host in hosts {
            let normalized = normalize_scope_host(&host);
            if !normalized.is_empty() {
                self.scope_hosts.insert(normalized);
            }
        }
        self.publish_event(AppStateEvent::ScopeUpdated(self.scope_snapshot()));
    }

    /// Adds a single host pattern to the scope.
    pub fn add_scope_host(&self, host: String) {
        let normalized = normalize_scope_host(&host);
        if !normalized.is_empty() {
            self.scope_hosts.insert(normalized);
            self.publish_event(AppStateEvent::ScopeUpdated(self.scope_snapshot()));
        }
    }

    /// Removes a host pattern from the scope.  Returns `true` if it was
    /// present.
    pub fn remove_scope_host(&self, host: &str) -> bool {
        let normalized = normalize_scope_host(host);
        let removed = self.scope_hosts.remove(&normalized).is_some();
        if removed {
            self.publish_event(AppStateEvent::ScopeUpdated(self.scope_snapshot()));
        }
        removed
    }

    /// Returns the current scope host patterns, sorted alphabetically.
    pub fn scope_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.scope_hosts.iter().map(|h| h.clone()).collect();
        hosts.sort();
        hosts
    }

    /// Returns a clone of the current upstream proxy settings.
    pub fn upstream_proxy_settings(&self) -> UpstreamProxySettings {
        self.upstream_proxy_settings
            .read()
            .map(|value| value.clone())
            .unwrap_or_default()
    }

    /// Replaces the upstream proxy settings, normalising the input first.
    pub fn set_upstream_proxy_settings(&self, settings: UpstreamProxySettings) {
        if let Ok(mut value) = self.upstream_proxy_settings.write() {
            *value = settings.normalized();
            self.publish_event(AppStateEvent::UpstreamProxySettingsUpdated(value.clone()));
        }
    }

    /// Returns `true` when `host` matches at least one scope pattern, or
    /// when the scope is empty ("everything is in scope").
    fn host_in_scope(&self, host: &str) -> bool {
        if self.scope_hosts.is_empty() {
            return true;
        }

        let host = host.trim().to_ascii_lowercase();
        for pattern in self.scope_hosts.iter() {
            if pattern.as_str() == "*" {
                return true;
            }
            if let Some(suffix) = pattern.strip_prefix("*.") {
                if host == suffix || host.ends_with(&format!(".{suffix}")) {
                    return true;
                }
            } else if host == *pattern {
                return true;
            }
        }

        false
    }
}

/// Trims whitespace and lowercases a scope host pattern.
fn normalize_scope_host(host: &str) -> String {
    host.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use tokio::time::{Duration, timeout};

    use super::*;
    use crate::model::{CapturedRequest, CapturedResponse, HeaderValuePair, now_unix_ms};

    fn fake_request() -> CapturedRequest {
        CapturedRequest {
            id: Uuid::new_v4(),
            created_at_unix_ms: now_unix_ms(),
            method: "GET".to_string(),
            uri: "http://example.com/test".to_string(),
            host: "example.com".to_string(),
            headers: vec![HeaderValuePair {
                name: "host".to_string(),
                value: "example.com".to_string(),
            }],
            body: bytes::Bytes::new(),
            raw: bytes::Bytes::from_static(b"GET /test HTTP/1.1\r\nhost: example.com\r\n\r\n"),
        }
    }

    fn fake_response(request_id: Uuid) -> CapturedResponse {
        CapturedResponse {
            request_id,
            created_at_unix_ms: now_unix_ms(),
            status: 200,
            headers: vec![],
            body: bytes::Bytes::from_static(b"ok"),
        }
    }

    #[tokio::test]
    async fn intercept_decision_is_delivered() {
        let state = AppState::new();
        let request = fake_request();
        let request_id = request.id;

        let rx = state.enqueue_intercept(request);
        state
            .continue_intercept(request_id, InterceptDecision::Forward)
            .expect("intercept should continue");

        let decision = timeout(Duration::from_millis(200), rx)
            .await
            .expect("oneshot should resolve")
            .expect("decision should be present");

        assert!(matches!(decision, InterceptDecision::Forward));
    }

    #[tokio::test]
    async fn disabling_intercept_flushes_pending_requests() {
        let state = AppState::new();
        state.set_intercept_enabled(true);

        let request = fake_request();
        let request_id = request.id;
        let rx = state.enqueue_intercept(request);

        state.set_intercept_enabled(false);

        let decision = timeout(Duration::from_millis(200), rx)
            .await
            .expect("oneshot should resolve")
            .expect("decision should be present");
        assert!(matches!(decision, InterceptDecision::Forward));
        assert!(state.pending_requests().iter().all(|r| r.id != request_id));
    }

    #[tokio::test]
    async fn response_intercept_decision_is_delivered() {
        let state = AppState::new();
        let request_id = Uuid::new_v4();
        let rx = state.enqueue_response_intercept(fake_response(request_id));

        state
            .continue_response_intercept(request_id, ResponseInterceptDecision::Forward)
            .expect("response intercept should continue");

        let decision = timeout(Duration::from_millis(200), rx)
            .await
            .expect("oneshot should resolve")
            .expect("decision should be present");

        assert!(matches!(decision, ResponseInterceptDecision::Forward));
    }

    #[tokio::test]
    async fn enqueue_intercept_emits_pending_intercepts_event() {
        let state = AppState::new();
        let mut events = state.subscribe_events();
        let request = fake_request();

        let _rx = state.enqueue_intercept(request.clone());

        let event = timeout(Duration::from_millis(200), events.recv())
            .await
            .expect("event should arrive")
            .expect("event should decode");

        match event {
            AppStateEvent::PendingIntercepts(snapshot) => {
                assert_eq!(snapshot.requests.len(), 1);
                assert_eq!(snapshot.requests[0].id, request.id);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[tokio::test]
    async fn set_mitm_emits_proxy_toggles_event() {
        let state = AppState::new();
        let mut events = state.subscribe_events();

        state.set_mitm_enabled(false);

        let event = timeout(Duration::from_millis(200), events.recv())
            .await
            .expect("event should arrive")
            .expect("event should decode");

        match event {
            AppStateEvent::ProxyToggles(snapshot) => {
                assert!(!snapshot.mitm_enabled);
                assert!(!snapshot.intercept_enabled);
                assert!(!snapshot.intercept_response_enabled);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn site_map_collects_paths() {
        let state = AppState::new();
        state.register_site_path("example.com", "/a");
        state.register_site_path("example.com", "/b");
        state.register_site_path("example.org", "/root");

        let map = state.site_map();
        assert_eq!(map.len(), 2);
        assert_eq!(map[0].0, "example.com");
        assert_eq!(map[1].0, "example.org");
    }

    #[test]
    fn scope_filters_site_map() {
        let state = AppState::new();
        state.set_scope_hosts(vec!["*.example.com".to_string()]);
        state.register_site_path("api.example.com", "/a");
        state.register_site_path("other.net", "/b");

        let map = state.site_map();
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].0, "api.example.com");
    }

    #[test]
    fn scope_hosts_round_trip() {
        let state = AppState::new();
        state.add_scope_host("EXAMPLE.COM".to_string());
        state.add_scope_host("*.foo.org".to_string());
        let scope = state.scope_hosts();
        assert_eq!(
            scope,
            vec!["*.foo.org".to_string(), "example.com".to_string()]
        );
        assert!(state.remove_scope_host("example.com"));
        assert_eq!(state.scope_hosts(), vec!["*.foo.org".to_string()]);
    }

    #[test]
    fn upstream_proxy_settings_round_trip_and_normalize() {
        let state = AppState::new();
        state.set_upstream_proxy_settings(UpstreamProxySettings {
            proxies: vec![
                UpstreamProxyEntry {
                    protocol: UpstreamProxyProtocol::Http,
                    address: " 127.0.0.1 ".to_string(),
                    port: 8080,
                },
                UpstreamProxyEntry {
                    protocol: UpstreamProxyProtocol::Socks5,
                    address: " ".to_string(),
                    port: 1080,
                },
            ],
            proxy_dns: true,
            chain_mode: UpstreamChainMode::RandomChain,
            min_chain_length: 0,
            max_chain_length: 0,
        });

        let value = state.upstream_proxy_settings();
        assert_eq!(value.proxies.len(), 1);
        assert_eq!(value.proxies[0].address, "127.0.0.1");
        assert!(value.proxy_dns);
        assert_eq!(value.chain_mode, UpstreamChainMode::RandomChain);
        assert_eq!(value.min_chain_length, 1);
        assert_eq!(value.max_chain_length, 1);
    }
}
