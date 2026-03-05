//! Encrypted Client Hello (ECH) auto-discovery and retry.
//!
//! When ECH is enabled (the default — controlled by `ROXY_ECH_ENABLED`)
//! the module:
//!
//! 1. Resolves **DNS HTTPS** records for the target host.
//! 2. Extracts and decodes the `ech=` / `echconfig=` parameter.
//! 3. Applies the resulting config list to the BoringSSL
//!    [`SslRef`] before the handshake.
//!
//! Results are cached per-host with TTLs derived from the DNS record.
//!
//! ## Environment variables
//!
//! | Variable | Default | Description |
//! |---|---|---|
//! | `ROXY_ECH_ENABLED` | `true` | Master enable/disable |
//! | `ROXY_ECH_GREASE` | `true` | Send GREASE ECH extension when no config is available |
//! | `ROXY_ECH_CONFIG_LIST_BASE64` | — | Static base64-encoded ECH config list (skips DNS) |

use std::{
    env,
    net::IpAddr,
    str::FromStr,
    sync::OnceLock,
    time::{Duration, Instant},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};
use boring::ssl::SslRef;
use dashmap::DashMap;
use hickory_resolver::{
    TokioAsyncResolver, config::ResolverConfig, lookup::Lookup, proto::rr::RecordType,
};
use tokio_boring::HandshakeError;
use tracing::{debug, warn};

/// Information extracted from a failed TLS handshake when the server
/// offers ECH retry configs.
#[derive(Clone, Debug)]
pub struct EchRetry {
    /// DER-encoded ECH config list sent by the server.
    pub config_list: Vec<u8>,
    /// Optional public name override for the retry attempt.
    pub public_name_override: Option<String>,
}

#[derive(Clone, Debug)]
struct EchClientSettings {
    enabled: bool,
    grease: bool,
    config_list: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct EchCacheEntry {
    config_list: Option<Vec<u8>>,
    expires_at: Instant,
}

const NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const MIN_POSITIVE_CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_POSITIVE_CACHE_TTL: Duration = Duration::from_secs(60 * 60);

/// Applies ECH configuration to an in-flight TLS handshake.
///
/// If `config_override` is `Some` it is used directly; otherwise the
/// module attempts auto-discovery via DNS HTTPS records. When neither
/// source provides a config list, GREASE ECH may still be enabled
/// based on the environment setting.
pub async fn apply_ech_client_config(ssl: &mut SslRef, host: &str, config_override: Option<&[u8]>) {
    let settings = ech_client_settings();
    if !settings.enabled {
        return;
    }

    if settings.grease {
        ssl.set_enable_ech_grease(true);
    }

    let config_list = if let Some(config_list) = config_override {
        Some(config_list.to_vec())
    } else if let Some(config_list) = settings.config_list.clone() {
        Some(config_list)
    } else {
        auto_discover_ech_config_list(host).await
    };

    if let Some(config_list) = config_list {
        if let Err(err) = ssl.set_ech_config_list(config_list.as_slice()) {
            warn!(%host, %err, "failed applying ECH config list to TLS client");
        }
    }
}

/// Inspects a TLS [`HandshakeError`] for ECH retry configs offered
/// by the server.
///
/// Returns `Some(EchRetry)` when the server indicates ECH should be
/// retried with updated configs, or `None` if the error is unrelated
/// to ECH.
///
/// **Safety note**: BoringSSL's `SSL_get0_ech_retry_configs` calls
/// `assert(0)` when invoked on a handshake that did not fail with
/// `SSL_R_ECH_REJECTED`.  The `tokio-boring` wrapper does not expose
/// the SSL reason code directly, so we guard the call by checking the
/// formatted error string for the `ECH_REJECTED` reason before
/// attempting to extract retry configs.
pub fn ech_retry_from_handshake_error<S>(err: &HandshakeError<S>) -> Option<EchRetry> {
    let ssl = err.ssl()?;

    // Only proceed when the handshake error is specifically an
    // authenticated ECH rejection.  Calling get_ech_retry_configs()
    // in any other state aborts the process via assert(0) inside
    // BoringSSL (encrypted_client_hello.cc).
    let err_msg = err.to_string();
    if !err_msg.contains("ECH_REJECTED") {
        return None;
    }

    let config_list = ssl.get_ech_retry_configs()?.to_vec();
    let public_name_override = ssl
        .get_ech_name_override()
        .map(|bytes| String::from_utf8_lossy(bytes).to_string());
    Some(EchRetry {
        config_list,
        public_name_override,
    })
}

fn ech_client_settings() -> &'static EchClientSettings {
    static SETTINGS: OnceLock<EchClientSettings> = OnceLock::new();
    SETTINGS.get_or_init(|| {
        let enabled = parse_bool_env("ROXY_ECH_ENABLED", true);
        let grease = parse_bool_env("ROXY_ECH_GREASE", true);
        let config_list = load_ech_config_list_from_env();
        EchClientSettings {
            enabled,
            grease,
            config_list,
        }
    })
}

fn load_ech_config_list_from_env() -> Option<Vec<u8>> {
    let raw = env::var("ROXY_ECH_CONFIG_LIST_BASE64").ok()?;
    if raw.trim().is_empty() {
        return None;
    }

    match STANDARD.decode(raw.trim()) {
        Ok(bytes) if !bytes.is_empty() => Some(bytes),
        Ok(_) => None,
        Err(err) => {
            warn!(%err, "failed decoding ROXY_ECH_CONFIG_LIST_BASE64");
            None
        }
    }
}

fn parse_bool_env(name: &str, default_value: bool) -> bool {
    let Some(value) = env::var(name).ok() else {
        return default_value;
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => default_value,
    }
}

fn ech_cache() -> &'static DashMap<String, EchCacheEntry> {
    static CACHE: OnceLock<DashMap<String, EchCacheEntry>> = OnceLock::new();
    CACHE.get_or_init(DashMap::new)
}

fn ech_resolver() -> Option<&'static TokioAsyncResolver> {
    static RESOLVER: OnceLock<Option<TokioAsyncResolver>> = OnceLock::new();
    RESOLVER
        .get_or_init(|| {
            #[cfg(any(unix, target_os = "windows"))]
            if let Ok(resolver) = TokioAsyncResolver::tokio_from_system_conf() {
                return Some(resolver);
            }

            Some(TokioAsyncResolver::tokio(
                ResolverConfig::default(),
                hickory_resolver::config::ResolverOpts::default(),
            ))
        })
        .as_ref()
}

async fn auto_discover_ech_config_list(host: &str) -> Option<Vec<u8>> {
    let host_key = normalize_host_for_lookup(host)?;
    if let Some(entry) = ech_cache().get(&host_key) {
        if entry.expires_at > Instant::now() {
            return entry.config_list.clone();
        }
    }
    ech_cache().remove(&host_key);

    let resolver = ech_resolver()?;
    let query_name = format!("{host_key}.");
    let lookup = match resolver.lookup(query_name, RecordType::HTTPS).await {
        Ok(lookup) => lookup,
        Err(err) => {
            debug!(%host, %err, "HTTPS record lookup failed for ECH discovery");
            cache_ech_lookup(host_key, None, NEGATIVE_CACHE_TTL);
            return None;
        }
    };

    debug!(
        %host,
        record_count = lookup.records().len(),
        "ECH HTTPS lookup completed"
    );
    let config_list = extract_ech_config_list(host, &lookup);
    let cache_ttl = if config_list.is_some() {
        positive_lookup_ttl(&lookup)
    } else {
        NEGATIVE_CACHE_TTL
    };
    if config_list.is_some() {
        debug!(%host, ttl_secs = cache_ttl.as_secs(), "ECH config list discovered from DNS");
    } else {
        debug!(%host, ttl_secs = cache_ttl.as_secs(), "ECH config list missing in DNS HTTPS records");
    }
    cache_ech_lookup(host_key, config_list.clone(), cache_ttl);
    config_list
}

fn normalize_host_for_lookup(host: &str) -> Option<String> {
    let normalized = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if IpAddr::from_str(&normalized).is_ok() {
        return None;
    }
    Some(normalized)
}

fn cache_ech_lookup(host: String, config_list: Option<Vec<u8>>, ttl: Duration) {
    ech_cache().insert(
        host,
        EchCacheEntry {
            config_list,
            expires_at: Instant::now() + ttl,
        },
    );
}

fn positive_lookup_ttl(lookup: &Lookup) -> Duration {
    let now = Instant::now();
    if lookup.valid_until() <= now {
        return MIN_POSITIVE_CACHE_TTL;
    }
    let ttl = lookup.valid_until().duration_since(now);
    ttl.clamp(MIN_POSITIVE_CACHE_TTL, MAX_POSITIVE_CACHE_TTL)
}

fn extract_ech_config_list(host: &str, lookup: &Lookup) -> Option<Vec<u8>> {
    for record in lookup.record_iter() {
        let record_text = record.to_string();
        debug!(%host, record = %record_text, "ECH DNS record candidate");
        if let Some(encoded) = parse_ech_param(&record_text) {
            if let Some(decoded) = decode_ech_config_list(encoded) {
                return Some(decoded);
            }
        }
        if let Some(data) = record.data() {
            let data_text = data.to_string();
            debug!(%host, record_data = %data_text, "ECH DNS record data candidate");
            if let Some(encoded) = parse_ech_param(&data_text) {
                if let Some(decoded) = decode_ech_config_list(encoded) {
                    return Some(decoded);
                }
            }
        }
    }
    None
}

fn parse_ech_param(value: &str) -> Option<&str> {
    let mut tail = if let Some(idx) = value.find("ech=") {
        value.get(idx + 4..)?
    } else if let Some(idx) = value.find("echconfig=") {
        value.get(idx + "echconfig=".len()..)?
    } else {
        return None;
    }
    .trim_start();
    if let Some(stripped) = tail.strip_prefix('"') {
        let end = stripped.find('"')?;
        tail = stripped.get(..end)?;
    } else {
        let end = tail
            .char_indices()
            .find_map(|(idx, ch)| {
                (ch.is_ascii_whitespace() || ch == ',' || ch == ';').then_some(idx)
            })
            .unwrap_or(tail.len());
        tail = tail.get(..end)?;
    }

    let tail = tail.trim();
    if tail.is_empty() { None } else { Some(tail) }
}

fn decode_ech_config_list(value: &str) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .or_else(|| URL_SAFE.decode(value).ok())
        .or_else(|| STANDARD_NO_PAD.decode(value).ok())
        .or_else(|| STANDARD.decode(value).ok())
        .filter(|bytes| !bytes.is_empty())?;
    normalize_ech_config_list(decoded)
}

fn normalize_ech_config_list(mut bytes: Vec<u8>) -> Option<Vec<u8>> {
    if bytes.len() < 4 {
        return None;
    }
    let advertised_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if advertised_len == bytes.len().saturating_sub(2) {
        return Some(bytes);
    }

    if bytes.len() > u16::MAX as usize {
        return None;
    }

    let mut prefixed = Vec::with_capacity(bytes.len() + 2);
    prefixed.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    prefixed.append(&mut bytes);
    Some(prefixed)
}
