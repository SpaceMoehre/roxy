use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type RequestId = Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderValuePair {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedRequest {
    pub id: RequestId,
    pub created_at_unix_ms: u128,
    pub method: String,
    pub uri: String,
    pub host: String,
    pub headers: Vec<HeaderValuePair>,
    pub body: Bytes,
    #[serde(default)]
    pub raw: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedResponse {
    pub request_id: RequestId,
    pub created_at_unix_ms: u128,
    pub status: u16,
    pub headers: Vec<HeaderValuePair>,
    pub body: Bytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapturedExchange {
    pub request: CapturedRequest,
    pub response: Option<CapturedResponse>,
    pub duration_ms: u128,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestMutation {
    pub raw: Option<Bytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResponseMutation {
    pub status: Option<u16>,
    pub headers: Option<Vec<HeaderValuePair>>,
    pub body: Option<Bytes>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", content = "payload")]
pub enum EventEnvelope {
    Exchange(CapturedExchange),
}

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

pub fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_millis(0))
        .as_millis()
}

pub fn apply_mutation(mut request: CapturedRequest, mutation: RequestMutation) -> CapturedRequest {
    if let Some(raw) = mutation.raw {
        request.raw = raw;
    }
    request
}

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
