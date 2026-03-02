//! roxy_core `raw_http` module.
//!
//! Exposes public types and functions used by the `roxy` runtime and API surface.

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use http::Uri;

use crate::model::HeaderValuePair;

#[derive(Clone, Debug)]
/// Represents `ParsedRequestBlob`.
///
/// See also: [`ParsedRequestBlob`].
pub struct ParsedRequestBlob {
    pub method: String,
    pub uri: String,
    pub host: String,
    pub headers: Vec<HeaderValuePair>,
    pub body: Bytes,
}

/// Builds `request blob`.
///
/// # Examples
/// ```
/// use roxy_core as _;
/// assert!(true);
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

/// Parses `request blob`.
///
/// # Examples
/// ```
/// use roxy_core as _;
/// assert!(true);
/// ```
///
/// # Errors
/// Returns an error when the operation cannot be completed.
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

fn header_value<'a>(headers: &'a [HeaderValuePair], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

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
