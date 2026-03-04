//! Lossless raw HTTP request blob parsing and building.
//!
//! roxy stores every captured request as a complete "wire-format" byte blob
//! (`request-line ‖ headers ‖ CRLFCRLF ‖ body`).  This module provides
//! [`build_request_blob`] to assemble such a blob from structured parts and
//! [`parse_request_blob`] to decompose one back into a [`ParsedRequestBlob`].
//!
//! The round-trip is intentionally lossless: building a blob and immediately
//! parsing it must produce the same structured fields that were fed in. This
//! guarantees that edits made through the intercept / repeater UI are
//! accurately reflected upstream.
//!
//! # Wire format
//!
//! ```text
//! METHOD SP request-target SP HTTP/1.1 CRLF
//! header-name: SP header-value CRLF
//! …
//! CRLF
//! [body bytes]
//! ```
//!
//! The parser also tolerates blobs that use bare `\n` instead of `\r\n`.

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http::Uri;

use crate::model::HeaderValuePair;

/// Structured representation of a raw HTTP request blob.
///
/// Produced by [`parse_request_blob`]; consumed by the proxy engine and the
/// outbound HTTP client when forwarding traffic upstream.
#[derive(Clone, Debug)]
pub struct ParsedRequestBlob {
    /// HTTP method (`GET`, `POST`, …).
    pub method: String,
    /// Fully-qualified URI including scheme and authority
    /// (e.g. `https://example.com/path`).
    pub uri: String,
    /// Target hostname (without port) extracted from the URI or `Host` header.
    pub host: String,
    /// Parsed request headers in original order.
    pub headers: Vec<HeaderValuePair>,
    /// Body bytes (everything after the blank line separator).
    pub body: Bytes,
}

/// Assembles a raw HTTP/1.1 request blob from structured parts.
///
/// The resulting [`Bytes`] contain the full wire-format blob:
/// `METHOD SP target SP HTTP/1.1 CRLF headers CRLF body`.
///
/// # Examples
///
/// ```
/// use roxy_core::raw_http::build_request_blob;
/// use roxy_core::model::HeaderValuePair;
///
/// let headers = vec![HeaderValuePair {
///     name: "Host".into(),
///     value: "example.com".into(),
/// }];
/// let blob = build_request_blob("GET", "/index.html", &headers, b"");
/// assert!(blob.starts_with(b"GET /index.html HTTP/1.1\r\n"));
/// ```
pub fn build_request_blob(
    method: &str,
    target: &str,
    headers: &[HeaderValuePair],
    body: &[u8],
) -> Bytes {
    let mut out = Vec::with_capacity(
        method.len()
            + target.len()
            + 16
            + headers
                .iter()
                .map(|h| h.name.len() + h.value.len() + 4)
                .sum::<usize>()
            + body.len(),
    );
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(target.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for header in headers {
        out.extend_from_slice(header.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(header.value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Bytes::from(out)
}

/// Parses a raw HTTP request blob into structured fields.
///
/// The parser handles three URI forms:
///
/// 1. **Absolute URI** — `GET http://example.com/path HTTP/1.1` → used as-is.
/// 2. **Origin-form** — `GET /path HTTP/1.1` + `Host: example.com` → scheme
///    is taken from `default_scheme`, authority from the `Host` header (or
///    `authority_hint` if `Host` is absent).
/// 3. **Bare `\n`** line endings — tolerated in addition to `\r\n`.
///
/// # Errors
///
/// Returns an error when:
///
/// * The blob has no `\r\n\r\n` (or `\n\n`) header/body separator.
/// * The request head is not valid UTF-8.
/// * The start line is missing a method or request-target.
/// * An origin-form request has no `Host` header and no `authority_hint`.
/// * A header line has no `:` separator.
pub fn parse_request_blob(
    raw: &[u8],
    default_scheme: &str,
    authority_hint: Option<&str>,
) -> Result<ParsedRequestBlob> {
    let (head, body) = split_request(raw)?;
    let head = std::str::from_utf8(head).context("request head is not UTF-8")?;
    let normalized = head.replace("\r\n", "\n");
    let mut lines = normalized.split('\n');

    let start_line = lines
        .next()
        .ok_or_else(|| anyhow!("request start-line is missing"))?;
    let mut parts = start_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("request method is missing"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| anyhow!("request target is missing"))?;

    let headers = lines
        .filter(|line| !line.is_empty())
        .map(parse_header_line)
        .collect::<Result<Vec<_>>>()?;

    let uri = if target.starts_with("http://") || target.starts_with("https://") {
        target.to_string()
    } else {
        let authority = header_value(&headers, "host")
            .map(ToOwned::to_owned)
            .or_else(|| authority_hint.map(ToOwned::to_owned))
            .ok_or_else(|| anyhow!("request blob missing host header"))?;
        let normalized_target = if target.starts_with('/') || target.starts_with('*') {
            target.to_string()
        } else {
            format!("/{target}")
        };
        format!("{default_scheme}://{authority}{normalized_target}")
    };

    let host = Uri::try_from(uri.as_str())
        .ok()
        .and_then(|u| u.host().map(ToOwned::to_owned))
        .or_else(|| {
            header_value(&headers, "host")
                .map(|value| value.split(':').next().unwrap_or(value).trim().to_string())
        })
        .unwrap_or_else(|| "unknown-host".to_string());

    Ok(ParsedRequestBlob {
        method,
        uri,
        host,
        headers,
        body: Bytes::copy_from_slice(body),
    })
}

/// Parses a single `name: value` header line.
fn parse_header_line(line: &str) -> Result<HeaderValuePair> {
    let idx = line
        .find(':')
        .ok_or_else(|| anyhow!("invalid header line '{line}'"))?;
    let name = line[..idx].trim();
    if name.is_empty() {
        return Err(anyhow!("invalid header line '{line}'"));
    }

    Ok(HeaderValuePair {
        name: name.to_string(),
        value: line[idx + 1..].trim().to_string(),
    })
}

/// Returns the value of the first header matching `name` (case-insensitive).
fn header_value<'a>(headers: &'a [HeaderValuePair], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

/// Splits a raw blob at the first `\r\n\r\n` (or `\n\n`) into head and body.
fn split_request(raw: &[u8]) -> Result<(&[u8], &[u8])> {
    if let Some(index) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        let head = &raw[..index];
        let body = &raw[index + 4..];
        return Ok((head, body));
    }
    if let Some(index) = raw.windows(2).position(|w| w == b"\n\n") {
        let head = &raw[..index];
        let body = &raw[index + 2..];
        return Ok((head, body));
    }
    Err(anyhow!(
        "request blob is missing header/body separator (expected CRLFCRLF or LFLF)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_uri_blob() {
        let raw =
            b"POST http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nX-Test: 1\r\n\r\nbody";
        let parsed = parse_request_blob(raw, "http", None).expect("parsed");
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.uri, "http://example.com/a?b=1");
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.body, Bytes::from_static(b"body"));
    }

    #[test]
    fn parses_origin_form_blob_with_host() {
        let raw = b"GET /login HTTP/1.1\r\nhost: target.tld:8443\r\n\r\n";
        let parsed = parse_request_blob(raw, "https", None).expect("parsed");
        assert_eq!(parsed.uri, "https://target.tld:8443/login");
        assert_eq!(parsed.host, "target.tld");
    }

    #[test]
    fn parses_lf_only_blob() {
        let raw = b"GET /lf HTTP/1.1\nHost: lf.example\n\n";
        let parsed = parse_request_blob(raw, "http", None).expect("parsed");
        assert_eq!(parsed.uri, "http://lf.example/lf");
    }

    #[test]
    fn builds_blob_round_trip() {
        let headers = vec![HeaderValuePair {
            name: "Host".to_string(),
            value: "a.test".to_string(),
        }];
        let blob = build_request_blob("GET", "/a", &headers, b"");
        let parsed = parse_request_blob(&blob, "http", None).expect("parsed");
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.uri, "http://a.test/a");
    }
}
