use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use dashmap::{DashMap, DashSet};
use thiserror::Error;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::model::{CapturedRequest, CapturedResponse, RequestMutation, ResponseMutation};

#[derive(Debug)]
pub enum InterceptDecision {
    Forward,
    Mutate(RequestMutation),
    Drop,
}

#[derive(Debug)]
pub enum ResponseInterceptDecision {
    Forward,
    Mutate(ResponseMutation),
    Drop,
}

#[derive(Debug)]
pub struct PendingIntercept {
    pub request: CapturedRequest,
    sender: Mutex<Option<oneshot::Sender<InterceptDecision>>>,
}

impl PendingIntercept {
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

#[derive(Debug)]
pub struct PendingResponseIntercept {
    pub response: CapturedResponse,
    sender: Mutex<Option<oneshot::Sender<ResponseInterceptDecision>>>,
}

impl PendingResponseIntercept {
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

#[derive(Debug)]
pub struct AppState {
    intercept_enabled: AtomicBool,
    intercept_response_enabled: AtomicBool,
    mitm_enabled: AtomicBool,
    pending_intercepts: DashMap<Uuid, Arc<PendingIntercept>>,
    pending_response_intercepts: DashMap<Uuid, Arc<PendingResponseIntercept>>,
    site_map: DashMap<String, DashSet<String>>,
    scope_hosts: DashSet<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            intercept_enabled: AtomicBool::new(false),
            intercept_response_enabled: AtomicBool::new(false),
            mitm_enabled: AtomicBool::new(true),
            pending_intercepts: DashMap::new(),
            pending_response_intercepts: DashMap::new(),
            site_map: DashMap::new(),
            scope_hosts: DashSet::new(),
        }
    }

    pub fn intercept_enabled(&self) -> bool {
        self.intercept_enabled.load(Ordering::Relaxed)
    }

    pub fn set_intercept_enabled(&self, enabled: bool) {
        self.intercept_enabled.store(enabled, Ordering::Relaxed);
        if !enabled {
            self.flush_pending_intercepts_forward();
        }
    }

    pub fn intercept_response_enabled(&self) -> bool {
        self.intercept_response_enabled.load(Ordering::Relaxed)
    }

    pub fn set_intercept_response_enabled(&self, enabled: bool) {
        self.intercept_response_enabled
            .store(enabled, Ordering::Relaxed);
    }

    pub fn mitm_enabled(&self) -> bool {
        self.mitm_enabled.load(Ordering::Relaxed)
    }

    pub fn set_mitm_enabled(&self, enabled: bool) {
        self.mitm_enabled.store(enabled, Ordering::Relaxed);
    }

    pub fn enqueue_intercept(
        &self,
        request: CapturedRequest,
    ) -> oneshot::Receiver<InterceptDecision> {
        let id = request.id;
        let (pending, rx) = PendingIntercept::new(request);
        self.pending_intercepts.insert(id, pending);
        rx
    }

    pub fn continue_intercept(
        &self,
        id: Uuid,
        decision: InterceptDecision,
    ) -> Result<(), StateError> {
        let entry = self
            .pending_intercepts
            .remove(&id)
            .ok_or(StateError::NotFound)?;
        entry.1.resolve(decision)
    }

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
    }

    pub fn enqueue_response_intercept(
        &self,
        response: CapturedResponse,
    ) -> oneshot::Receiver<ResponseInterceptDecision> {
        let id = response.request_id;
        let (pending, rx) = PendingResponseIntercept::new(response);
        self.pending_response_intercepts.insert(id, pending);
        rx
    }

    pub fn continue_response_intercept(
        &self,
        id: Uuid,
        decision: ResponseInterceptDecision,
    ) -> Result<(), StateError> {
        let entry = self
            .pending_response_intercepts
            .remove(&id)
            .ok_or(StateError::NotFound)?;
        entry.1.resolve(decision)
    }

    pub fn pending_responses(&self) -> Vec<CapturedResponse> {
        let mut rows: Vec<CapturedResponse> = self
            .pending_response_intercepts
            .iter()
            .map(|entry| entry.value().response.clone())
            .collect();
        rows.sort_by_key(|r| r.created_at_unix_ms);
        rows
    }

    pub fn register_site_path(&self, host: impl Into<String>, path: impl Into<String>) {
        let host = host.into().trim().to_ascii_lowercase();
        if !self.host_in_scope(&host) {
            return;
        }
        let path = path.into();
        self.site_map.entry(host).or_default().insert(path);
    }

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

    pub fn set_scope_hosts(&self, hosts: Vec<String>) {
        self.scope_hosts.clear();
        for host in hosts {
            let normalized = normalize_scope_host(&host);
            if !normalized.is_empty() {
                self.scope_hosts.insert(normalized);
            }
        }
    }

    pub fn add_scope_host(&self, host: String) {
        let normalized = normalize_scope_host(&host);
        if !normalized.is_empty() {
            self.scope_hosts.insert(normalized);
        }
    }

    pub fn remove_scope_host(&self, host: &str) -> bool {
        let normalized = normalize_scope_host(host);
        self.scope_hosts.remove(&normalized).is_some()
    }

    pub fn scope_hosts(&self) -> Vec<String> {
        let mut hosts: Vec<String> = self.scope_hosts.iter().map(|h| h.clone()).collect();
        hosts.sort();
        hosts
    }

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
}
