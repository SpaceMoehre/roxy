//! Core domain types shared across the roxy workspace.
//!
//! Every HTTP exchange captured by the proxy is represented as a
//! [`CapturedRequest`] / [`CapturedResponse`] pair bundled into a
//! [`CapturedExchange`].  These types are serialisable with `serde` so they
//! can be persisted to `roxy_storage` and pushed over
//! WebSocket via [`EventEnvelope`].
//!
//! Mutation types ([`RequestMutation`], [`ResponseMutation`]) describe
//! targeted edits that the intercept UI applies to in-flight exchanges.
//!
//! Utility functions [`headers_to_pairs`], [`now_unix_ms`], [`apply_mutation`],
//! and [`apply_response_mutation`] are re-exported at the crate root.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Strongly-typed alias for the UUID that identifies a single captured request.
pub type RequestId = Uuid;

/// A single HTTP header represented as owned name/value strings.
///
/// The proxy stores headers in this form rather than [`http::HeaderMap`] so
/// the values can be round-tripped through JSON without loss.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderValuePair {
    /// Header name, e.g. `"content-type"`.
    pub name: String,
    /// Header value, e.g. `"application/json"`.
    pub value: String,
}

/// A complete HTTP request as captured by the proxy engine.
///
/// The `raw` field always contains the full wire-format bytes (request-line +
/// headers + body) exactly as they will be forwarded upstream.  The structured
/// fields (`method`, `uri`, …) are derived from the raw blob and updated
/// whenever the blob is re-parsed after a mutation or middleware transform.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedRequest {
    /// Unique identifier assigned when the request enters the proxy.
    pub id: RequestId,
    /// Wall-clock timestamp (milliseconds since Unix epoch) when the request
    /// was first seen.
    pub created_at_unix_ms: u128,
    /// HTTP method, e.g. `"GET"`, `"POST"`.
    pub method: String,
    /// Fully-qualified request URI including scheme and authority.
    pub uri: String,
    /// Target hostname extracted from the URI or the `Host` header.
    pub host: String,
    /// Request headers in stable insertion order.
    pub headers: Vec<HeaderValuePair>,
    /// Decoded request body bytes (may be empty for bodyless methods).
    pub body: Bytes,
    /// Complete raw request blob (request-line + headers + body) in wire
    /// format.
    #[serde(default)]
    pub raw: Bytes,
}

/// A complete HTTP response paired with the request that triggered it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedResponse {
    /// The [`RequestId`] of the originating request.
    pub request_id: RequestId,
    /// Wall-clock timestamp (milliseconds since Unix epoch) when the response
    /// was received.
    pub created_at_unix_ms: u128,
    /// Numeric HTTP status code, e.g. `200`, `404`.
    pub status: u16,
    /// Response headers in order.
    pub headers: Vec<HeaderValuePair>,
    /// Decoded response body bytes (content-encoding already unwrapped by the
    /// proxy engine).
    pub body: Bytes,
}

/// A request/response pair with timing and optional error context.
///
/// This is the primary unit that flows through the event pipeline, is
/// persisted to storage, and is broadcast over WebSocket to the dashboard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedExchange {
    /// The captured request.
    pub request: CapturedRequest,
    /// The captured response, or `None` if the exchange was dropped or errored
    /// before a response could be obtained.
    pub response: Option<CapturedResponse>,
    /// Total wall-clock duration of the round-trip, in milliseconds.
    pub duration_ms: u128,
    /// Human-readable error message when the exchange did not complete
    /// normally (e.g. "response dropped by interceptor").
    pub error: Option<String>,
}

/// Describes a targeted edit to an in-flight request.
///
/// Currently the only supported mutation is replacing the entire raw blob;
/// the proxy re-parses the blob after applying the mutation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestMutation {
    /// Replacement raw request blob.  When `Some`, the proxy replaces the
    /// entire wire-format blob and re-parses method/uri/host/headers/body
    /// from the new value.
    pub raw: Option<Bytes>,
}

/// Describes a targeted edit to an in-flight response.
///
/// Each field is optional; only fields set to `Some` are overwritten.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseMutation {
    /// Override the HTTP status code.
    pub status: Option<u16>,
    /// Replace the entire header list.
    pub headers: Option<Vec<HeaderValuePair>>,
    /// Replace the response body bytes.
    pub body: Option<Bytes>,
}

/// Envelope pushed through the event pipeline and broadcast over WebSocket.
///
/// Tagged with `#[serde(tag = "event", content = "payload")]` so each variant
/// serialises as `{"event": "<tag>", "payload": {…}}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", content = "payload")]
pub enum EventEnvelope {
    /// A completed (or failed) HTTP exchange.
    Exchange(CapturedExchange),
}

/// Converts an [`http::HeaderMap`] into a `Vec<HeaderValuePair>`, discarding
/// any header values that are not valid UTF-8.
///
/// # Examples
///
/// ```
/// use roxy_core::model::{headers_to_pairs, HeaderValuePair};
///
/// let mut map = http::HeaderMap::new();
/// map.insert("content-type", "text/plain".parse().unwrap());
/// let pairs = headers_to_pairs(&map);
/// assert_eq!(pairs.len(), 1);
/// assert_eq!(pairs[0].name, "content-type");
/// ```
pub fn headers_to_pairs(headers: &HeaderMap) -> Vec<HeaderValuePair> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|v| HeaderValuePair {
                name: name.to_string(),
                value: v.to_owned(),
            })
        })
        .collect()
}

/// Returns the current wall-clock time as milliseconds since the Unix epoch.
///
/// Falls back to `0` if the system clock is before the epoch (should never
/// happen in practice).
///
/// # Examples
///
/// ```
/// let ts = roxy_core::model::now_unix_ms();
/// assert!(ts > 1_700_000_000_000); // well past 2023
/// ```
pub fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_millis(0))
        .as_millis()
}

/// Applies a [`RequestMutation`] to a [`CapturedRequest`], returning the
/// (possibly modified) request.
///
/// Currently only the `raw` field is supported — when set, the entire raw
/// blob is replaced. The caller is responsible for re-parsing structured
/// fields from the new blob afterwards.
pub fn apply_mutation(mut request: CapturedRequest, mutation: RequestMutation) -> CapturedRequest {
    if let Some(raw) = mutation.raw {
        request.raw = raw;
    }
    request
}

/// Applies a [`ResponseMutation`] to a [`CapturedResponse`], returning the
/// (possibly modified) response.
///
/// Only fields set to `Some` in the mutation are overwritten; `None` fields
/// leave the original value intact.
pub fn apply_response_mutation(
    mut response: CapturedResponse,
    mutation: ResponseMutation,
) -> CapturedResponse {
    if let Some(status) = mutation.status {
        response.status = status;
    }
    if let Some(headers) = mutation.headers {
        response.headers = headers;
    }
    if let Some(body) = mutation.body {
        response.body = body;
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_mutation_overrides_fields() {
        let original = CapturedRequest {
            id: Uuid::new_v4(),
            created_at_unix_ms: now_unix_ms(),
            method: "GET".to_string(),
            uri: "http://example.com".to_string(),
            host: "example.com".to_string(),
            headers: vec![HeaderValuePair {
                name: "x-a".to_string(),
                value: "1".to_string(),
            }],
            body: Bytes::from_static(b"aaa"),
            raw: Bytes::from_static(b"GET / HTTP/1.1\r\nhost: example.com\r\n\r\naaa"),
        };

        let mutated = apply_mutation(
            original,
            RequestMutation {
                raw: Some(Bytes::from_static(
                    b"POST /mutated HTTP/1.1\r\nhost: example.com\r\n\r\nbbb",
                )),
            },
        );

        assert_eq!(
            mutated.raw,
            Bytes::from_static(b"POST /mutated HTTP/1.1\r\nhost: example.com\r\n\r\nbbb")
        );
        assert_eq!(mutated.host, "example.com");
    }

    #[test]
    fn response_mutation_overrides_fields() {
        let original = CapturedResponse {
            request_id: Uuid::new_v4(),
            created_at_unix_ms: now_unix_ms(),
            status: 200,
            headers: vec![HeaderValuePair {
                name: "x-a".to_string(),
                value: "1".to_string(),
            }],
            body: Bytes::from_static(b"ok"),
        };

        let mutated = apply_response_mutation(
            original,
            ResponseMutation {
                status: Some(418),
                headers: None,
                body: Some(Bytes::from_static(b"teapot")),
            },
        );

        assert_eq!(mutated.status, 418);
        assert_eq!(mutated.body, Bytes::from_static(b"teapot"));
    }
}
