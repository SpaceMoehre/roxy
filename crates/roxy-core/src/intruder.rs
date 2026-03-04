//! Automated HTTP fuzzer with configurable attack strategies.
//!
//! This module implements a Burp Suite–style "Intruder" that sends
//! parameterised HTTP requests in bulk. Users define a **request blob
//! template** containing `{{key}}` placeholders and optional `§…§`
//! section markers, attach one or more [`IntruderPayloadSet`]s, and
//! choose a [`IntruderStrategy`].
//!
//! ## Attack strategies
//!
//! | Strategy | Behaviour |
//! |---|---|
//! | [`IntruderStrategy::ClusterBomb`] | Cartesian product of all payload sets |
//! | [`IntruderStrategy::Sniper`] | Cycles one position at a time, baseline for the rest |
//!
//! ## Concurrency
//!
//! Jobs are executed on a Tokio [`JoinSet`] with
//! a configurable concurrency cap (default 16, max 256). Results stream
//! through a [`broadcast`] channel as
//! [`IntruderEvent`]s so the UI can update in real time.

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::{
    sync::{RwLock, broadcast},
    task::JoinSet,
};
use uuid::Uuid;

use crate::{
    model::now_unix_ms,
    outbound::send_parsed_request,
    raw_http::{ParsedRequestBlob, parse_request_blob},
};

/// A named list of values to substitute into a request template.
///
/// Each set is identified by a unique `key` that corresponds to a
/// `{{key}}` placeholder in the request blob template.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntruderPayloadSet {
    /// Placeholder name — must be unique within a single job spec.
    pub key: String,
    /// The values to iterate over for this placeholder.
    pub values: Vec<String>,
}

/// Determines how payload sets are combined into concrete request vectors.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntruderStrategy {
    /// Cartesian product — every combination of every payload set value.
    ///
    /// With two sets of sizes *m* and *n* this produces *m × n* requests.
    ClusterBomb,
    /// One position at a time — each set is iterated while the others
    /// stay at their first (baseline) value.
    ///
    /// With two sets of sizes *m* and *n* this produces *m + n* requests.
    Sniper,
}

impl Default for IntruderStrategy {
    fn default() -> Self {
        Self::ClusterBomb
    }
}

/// Full specification for an intruder job submitted by the user.
///
/// The `request_blob_template` may contain `{{key}}` placeholders that
/// map to [`IntruderPayloadSet`] keys, and `§…§` section markers for
/// inline value replacement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntruderJobSpec {
    /// Human-readable label shown in the jobs list.
    pub name: String,
    /// Raw HTTP request with placeholder / marker syntax.
    pub request_blob_template: String,
    /// Fallback scheme if one cannot be inferred from the template
    /// (defaults to `"http"`).
    #[serde(default)]
    pub default_scheme: Option<String>,
    /// Payload sets whose values are substituted into the template.
    #[serde(default)]
    pub payload_sets: Vec<IntruderPayloadSet>,
    /// Combination strategy (defaults to [`IntruderStrategy::ClusterBomb`]).
    #[serde(default)]
    pub strategy: IntruderStrategy,
    /// Maximum number of in-flight requests (default 16, clamped to 1–256).
    pub concurrency: Option<usize>,
    /// Per-request timeout in milliseconds (default 15 000).
    pub timeout_ms: Option<u64>,
}

/// Lifecycle state of an intruder job.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntruderJobStatus {
    /// Job has been queued but execution has not started.
    Pending,
    /// Requests are actively being sent.
    Running,
    /// All requests finished without a fatal error.
    Completed,
    /// The job was aborted due to an unrecoverable error.
    Failed,
}

/// Outcome of a single intruder request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntruderResult {
    /// Zero-based ordinal within the job.
    pub sequence: usize,
    /// The concrete payload key → value map used for this request.
    pub payloads: BTreeMap<String, String>,
    /// HTTP status code, absent when the request itself failed.
    pub status: Option<u16>,
    /// Round-trip time in milliseconds.
    pub duration_ms: u128,
    /// Response body size in bytes.
    pub response_size: usize,
    /// The fully-rendered raw request that was sent.
    pub request_blob: String,
    /// The raw response (status-line + headers + body), if received.
    pub response_blob: Option<String>,
    /// Error message when the request could not be completed.
    pub error: Option<String>,
}

/// Point-in-time view of a job's progress, safe to serialise and send
/// to the UI.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntruderJobSnapshot {
    /// Unique job identifier.
    pub id: Uuid,
    /// Human-readable label.
    pub name: String,
    /// Unix epoch timestamp (ms) when the job was created.
    pub created_at_unix_ms: u128,
    /// When execution actually began (first request sent).
    pub started_at_unix_ms: Option<u128>,
    /// When the last result was collected.
    pub ended_at_unix_ms: Option<u128>,
    /// Current lifecycle state.
    pub status: IntruderJobStatus,
    /// Number of requests that have finished so far.
    pub completed: usize,
    /// Total number of requests that will be sent.
    pub total: usize,
    /// Fatal error message, present only when `status == Failed`.
    pub error: Option<String>,
}

/// Real-time event broadcast by the intruder subsystem.
///
/// Sent over a [`broadcast`] channel and
/// forwarded to WebSocket clients.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", content = "payload")]
pub enum IntruderEvent {
    /// The job snapshot changed (status transition or progress tick).
    JobUpdated(IntruderJobSnapshot),
    /// A single request completed (success or per-request error).
    JobResult {
        /// Which job produced this result.
        job_id: Uuid,
        /// The individual request outcome.
        result: IntruderResult,
    },
}

/// Full details of a job including its first *N* results.
///
/// Returned by [`IntruderManager::get_job_details`] and serialised to
/// the REST API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntruderJobDetails {
    /// Current progress snapshot.
    pub snapshot: IntruderJobSnapshot,
    /// The first `result_limit` results (oldest first).
    pub results: Vec<IntruderResult>,
}

#[derive(Debug)]
struct IntruderJobState {
    snapshot: IntruderJobSnapshot,
    results: Vec<IntruderResult>,
}

/// Shared, cheaply cloneable handle to the intruder subsystem.
///
/// Internally wraps a [`DashMap`] of live jobs and a
/// [`broadcast::Sender`] for event
/// distribution. Safe to share across threads and Tokio tasks.
#[derive(Clone)]
pub struct IntruderManager {
    /// All known jobs keyed by UUID.
    jobs: Arc<DashMap<Uuid, Arc<RwLock<IntruderJobState>>>>,
    /// Fan-out channel for [`IntruderEvent`]s.
    events_tx: broadcast::Sender<IntruderEvent>,
}

impl Default for IntruderManager {
    fn default() -> Self {
        let (events_tx, _) = broadcast::channel(2048);
        Self {
            jobs: Arc::new(DashMap::new()),
            events_tx,
        }
    }
}

impl IntruderManager {
    /// Returns a new receiver for the intruder event broadcast channel.
    ///
    /// Each receiver independently sees every [`IntruderEvent`] emitted
    /// after it subscribes. Lagging receivers will lose older events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<IntruderEvent> {
        self.events_tx.subscribe()
    }

    /// Validates the spec, computes payload vectors, and spawns a
    /// background Tokio task that sends the requests.
    ///
    /// Returns the job's UUID immediately; progress is streamed via
    /// [`subscribe_events`](Self::subscribe_events).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - a payload key is empty or duplicated,
    /// - a payload set contains no values, or
    /// - the cartesian product exceeds 100 000 combinations.
    pub async fn start_job(&self, spec: IntruderJobSpec) -> Result<Uuid> {
        validate_payload_sets(&spec.payload_sets)?;
        let payload_vectors = build_payload_vectors(&spec.payload_sets, spec.strategy.clone())?;
        let total = payload_vectors.len();

        let id = Uuid::new_v4();
        let snapshot = IntruderJobSnapshot {
            id,
            name: spec.name.clone(),
            created_at_unix_ms: now_unix_ms(),
            started_at_unix_ms: None,
            ended_at_unix_ms: None,
            status: IntruderJobStatus::Pending,
            completed: 0,
            total,
            error: None,
        };

        let job_state = Arc::new(RwLock::new(IntruderJobState {
            snapshot,
            results: Vec::with_capacity(total.min(512)),
        }));
        self.jobs.insert(id, job_state.clone());

        let manager = self.clone();
        tokio::spawn(async move {
            if let Err(err) = manager
                .execute_job(job_state.clone(), spec, payload_vectors)
                .await
            {
                let mut guard = job_state.write().await;
                guard.snapshot.status = IntruderJobStatus::Failed;
                guard.snapshot.ended_at_unix_ms = Some(now_unix_ms());
                guard.snapshot.error = Some(err.to_string());
                let _ = manager
                    .events_tx
                    .send(IntruderEvent::JobUpdated(guard.snapshot.clone()));
            }
        });

        Ok(id)
    }

    /// Returns snapshots for every known job, sorted oldest-first by
    /// creation time.
    pub async fn list_jobs(&self) -> Vec<IntruderJobSnapshot> {
        let mut rows = Vec::with_capacity(self.jobs.len());
        for row in &*self.jobs {
            rows.push(row.value().read().await.snapshot.clone());
        }
        rows.sort_by_key(|r| r.created_at_unix_ms);
        rows
    }

    /// Returns the current snapshot for a single job, or `None` if
    /// the UUID is unknown.
    pub async fn get_job(&self, id: Uuid) -> Option<IntruderJobSnapshot> {
        let state = self.jobs.get(&id)?;
        Some(state.read().await.snapshot.clone())
    }

    /// Returns a page of [`IntruderResult`]s for the given job.
    ///
    /// `offset` and `limit` are applied to the internal results vector
    /// (oldest first). Returns `None` if the job UUID is unknown.
    pub async fn get_job_results(
        &self,
        id: Uuid,
        offset: usize,
        limit: usize,
    ) -> Option<Vec<IntruderResult>> {
        let state = self.jobs.get(&id)?;
        let guard = state.read().await;
        let rows = guard
            .results
            .iter()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        Some(rows)
    }

    /// Returns the snapshot together with the first `result_limit`
    /// results for a single job.
    pub async fn get_job_details(
        &self,
        id: Uuid,
        result_limit: usize,
    ) -> Option<IntruderJobDetails> {
        let state = self.jobs.get(&id)?;
        let guard = state.read().await;
        Some(IntruderJobDetails {
            snapshot: guard.snapshot.clone(),
            results: guard.results.iter().take(result_limit).cloned().collect(),
        })
    }

    /// Removes a job and all its results from memory.
    ///
    /// Returns `true` if the job existed.
    pub fn remove_job(&self, id: Uuid) -> bool {
        self.jobs.remove(&id).is_some()
    }

    async fn execute_job(
        &self,
        state: Arc<RwLock<IntruderJobState>>,
        spec: IntruderJobSpec,
        payload_vectors: Vec<BTreeMap<String, String>>,
    ) -> Result<()> {
        let timeout = Duration::from_millis(spec.timeout_ms.unwrap_or(15_000));

        {
            let mut guard = state.write().await;
            guard.snapshot.status = IntruderJobStatus::Running;
            guard.snapshot.started_at_unix_ms = Some(now_unix_ms());
            let _ = self
                .events_tx
                .send(IntruderEvent::JobUpdated(guard.snapshot.clone()));
        }

        let concurrency = spec.concurrency.unwrap_or(16).clamp(1, 256);
        let mut join_set = JoinSet::new();

        for (sequence, payloads) in payload_vectors.into_iter().enumerate() {
            let payloads_cloned = payloads.clone();
            let request = build_attack_request(&spec, payloads)?;

            join_set.spawn(async move {
                execute_attack(sequence, payloads_cloned, request, timeout).await
            });

            if join_set.len() >= concurrency {
                self.consume_one_result(&state, &mut join_set).await;
            }
        }

        while !join_set.is_empty() {
            self.consume_one_result(&state, &mut join_set).await;
        }

        {
            let mut guard = state.write().await;
            if guard.snapshot.status != IntruderJobStatus::Failed {
                guard.snapshot.status = IntruderJobStatus::Completed;
                guard.snapshot.ended_at_unix_ms = Some(now_unix_ms());
            }
            let _ = self
                .events_tx
                .send(IntruderEvent::JobUpdated(guard.snapshot.clone()));
        }

        Ok(())
    }

    async fn consume_one_result(
        &self,
        state: &Arc<RwLock<IntruderJobState>>,
        join_set: &mut JoinSet<IntruderResult>,
    ) {
        if let Some(joined) = join_set.join_next().await {
            let result = match joined {
                Ok(row) => row,
                Err(err) => IntruderResult {
                    sequence: 0,
                    payloads: BTreeMap::new(),
                    status: None,
                    duration_ms: 0,
                    response_size: 0,
                    request_blob: String::new(),
                    response_blob: None,
                    error: Some(format!("intruder worker join error: {err}")),
                },
            };

            let mut guard = state.write().await;
            guard.snapshot.completed += 1;
            guard.results.push(result.clone());
            let snapshot = guard.snapshot.clone();
            drop(guard);

            let _ = self.events_tx.send(IntruderEvent::JobResult {
                job_id: snapshot.id,
                result,
            });
            let _ = self.events_tx.send(IntruderEvent::JobUpdated(snapshot));
        }
    }
}

struct PreparedRequest {
    parsed: ParsedRequestBlob,
    request_blob: String,
}

fn build_attack_request(
    spec: &IntruderJobSpec,
    payloads: BTreeMap<String, String>,
) -> Result<PreparedRequest> {
    let rendered = render_template(&spec.request_blob_template, &payloads);
    let marker_value = marker_payload_value(&payloads).map(String::as_str);
    let request_blob = apply_section_markers(&rendered, marker_value)
        .context("invalid § marker usage in intruder request blob")?;
    let inferred_default_scheme = infer_default_scheme_from_request_blob(&request_blob);
    let default_scheme = spec
        .default_scheme
        .as_deref()
        .or(inferred_default_scheme)
        .unwrap_or("http");
    let parsed = parse_request_blob(request_blob.as_bytes(), default_scheme, None)
        .context("invalid intruder request blob")?;
    Ok(PreparedRequest {
        parsed,
        request_blob,
    })
}

fn marker_payload_value(payloads: &BTreeMap<String, String>) -> Option<&String> {
    payloads.get("marker").or_else(|| payloads.values().next())
}

fn apply_section_markers(template: &str, value: Option<&str>) -> Result<String> {
    let marker_positions: Vec<usize> = template.match_indices('§').map(|(idx, _)| idx).collect();
    if marker_positions.is_empty() {
        return Ok(template.to_string());
    }

    if marker_positions.len() % 2 != 0 {
        return Err(anyhow!("unmatched § marker in request template"));
    }

    let replacement =
        value.ok_or_else(|| anyhow!("request template contains § markers but no payload value"))?;

    let marker_len = '§'.len_utf8();
    let mut out = String::with_capacity(template.len());
    let mut cursor = 0usize;
    for pair in marker_positions.chunks_exact(2) {
        let start = pair[0];
        let end = pair[1];
        out.push_str(&template[cursor..start]);
        out.push_str(replacement);
        cursor = end + marker_len;
    }
    out.push_str(&template[cursor..]);
    Ok(out)
}

fn infer_default_scheme_from_request_blob(request_blob: &str) -> Option<&'static str> {
    let mut lines = request_blob.lines();
    let request_line = lines.next()?.trim();
    let target = request_line.split_whitespace().nth(1)?.trim();

    if target.starts_with("https://") {
        return Some("https");
    }
    if target.starts_with("http://") {
        return Some("http");
    }

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        let Some((name, value)) = trimmed.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("host") {
            continue;
        }
        let host_value = value.trim().to_ascii_lowercase();
        if host_value.ends_with(":443") {
            return Some("https");
        }
        if host_value.ends_with(":80") {
            return Some("http");
        }
    }

    None
}

async fn execute_attack(
    sequence: usize,
    payloads: BTreeMap<String, String>,
    request: PreparedRequest,
    timeout: Duration,
) -> IntruderResult {
    let started = std::time::Instant::now();
    let request_blob = request.request_blob;
    let parsed_request = request.parsed;

    let response = async {
        let resp = send_parsed_request(parsed_request, timeout, true)
            .await
            .context("request failed")?;
        let status = resp.status.as_u16();
        let mut headers_text = String::new();
        for (name, value) in &resp.headers {
            if let Ok(v) = value.to_str() {
                headers_text.push_str(name.as_str());
                headers_text.push_str(": ");
                headers_text.push_str(v);
                headers_text.push_str("\r\n");
            }
        }
        let bytes = resp.body;
        let body_text = String::from_utf8_lossy(&bytes);
        let response_blob = format!("HTTP/1.1 {status}\r\n{headers_text}\r\n{body_text}");
        Ok::<(u16, usize, String), anyhow::Error>((status, bytes.len(), response_blob))
    }
    .await;

    match response {
        Ok((status, response_size, response_blob)) => IntruderResult {
            sequence,
            payloads,
            status: Some(status),
            duration_ms: started.elapsed().as_millis(),
            response_size,
            request_blob,
            response_blob: Some(response_blob),
            error: None,
        },
        Err(err) => IntruderResult {
            sequence,
            payloads,
            status: None,
            duration_ms: started.elapsed().as_millis(),
            response_size: 0,
            request_blob,
            response_blob: None,
            error: Some(err.to_string()),
        },
    }
}

fn validate_payload_sets(payload_sets: &[IntruderPayloadSet]) -> Result<()> {
    let mut keys = HashSet::new();
    for set in payload_sets {
        if set.key.trim().is_empty() {
            return Err(anyhow!("payload key cannot be empty"));
        }
        if set.values.is_empty() {
            return Err(anyhow!("payload set '{}' has no values", set.key));
        }
        if !keys.insert(set.key.clone()) {
            return Err(anyhow!("duplicate payload key '{}'", set.key));
        }
    }
    Ok(())
}

fn build_payload_vectors(
    payload_sets: &[IntruderPayloadSet],
    strategy: IntruderStrategy,
) -> Result<Vec<BTreeMap<String, String>>> {
    if payload_sets.is_empty() {
        return Ok(vec![BTreeMap::new()]);
    }

    let vectors = match strategy {
        IntruderStrategy::ClusterBomb => build_cluster_bomb(payload_sets),
        IntruderStrategy::Sniper => build_sniper(payload_sets),
    };

    if vectors.len() > 100_000 {
        return Err(anyhow!(
            "intruder produced too many payload combinations ({})",
            vectors.len()
        ));
    }

    Ok(vectors)
}

fn build_cluster_bomb(payload_sets: &[IntruderPayloadSet]) -> Vec<BTreeMap<String, String>> {
    let mut out = vec![BTreeMap::new()];
    for set in payload_sets {
        let mut next = Vec::with_capacity(out.len().saturating_mul(set.values.len()));
        for row in &out {
            for value in &set.values {
                let mut cloned = row.clone();
                cloned.insert(set.key.clone(), value.clone());
                next.push(cloned);
            }
        }
        out = next;
    }
    out
}

fn build_sniper(payload_sets: &[IntruderPayloadSet]) -> Vec<BTreeMap<String, String>> {
    let mut baseline = BTreeMap::new();
    for set in payload_sets {
        baseline.insert(set.key.clone(), set.values[0].clone());
    }

    let mut out = Vec::new();
    for set in payload_sets {
        for value in &set.values {
            let mut row = baseline.clone();
            row.insert(set.key.clone(), value.clone());
            out.push(row);
        }
    }
    out
}

/// Substitutes `{{key}}` placeholders in `template` with values from
/// `payloads`.
///
/// # Examples
///
/// ```
/// use std::collections::BTreeMap;
/// use roxy_core::intruder::render_template;
///
/// let payloads = BTreeMap::from([
///     ("host".to_string(), "example.com".to_string()),
///     ("id".to_string(), "42".to_string()),
/// ]);
/// assert_eq!(
///     render_template("https://{{host}}/a/{{id}}", &payloads),
///     "https://example.com/a/42",
/// );
/// ```
pub fn render_template(template: &str, payloads: &BTreeMap<String, String>) -> String {
    let mut rendered = template.to_string();
    for (key, value) in payloads {
        rendered = rendered.replace(&format!("{{{{{key}}}}}"), value);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_bomb_cartesian_product() {
        let sets = vec![
            IntruderPayloadSet {
                key: "a".to_string(),
                values: vec!["1".to_string(), "2".to_string()],
            },
            IntruderPayloadSet {
                key: "b".to_string(),
                values: vec!["x".to_string(), "y".to_string()],
            },
        ];

        let vectors = build_payload_vectors(&sets, IntruderStrategy::ClusterBomb).expect("vectors");
        assert_eq!(vectors.len(), 4);
    }

    #[test]
    fn sniper_mode_generates_one_axis_at_a_time() {
        let sets = vec![
            IntruderPayloadSet {
                key: "a".to_string(),
                values: vec!["1".to_string(), "2".to_string()],
            },
            IntruderPayloadSet {
                key: "b".to_string(),
                values: vec!["x".to_string(), "y".to_string(), "z".to_string()],
            },
        ];

        let vectors = build_payload_vectors(&sets, IntruderStrategy::Sniper).expect("vectors");
        assert_eq!(vectors.len(), 5);
    }

    #[test]
    fn template_rendering_replaces_placeholders() {
        let payloads = BTreeMap::from([
            ("host".to_string(), "example.com".to_string()),
            ("id".to_string(), "42".to_string()),
        ]);

        let rendered = render_template("https://{{host}}/a/{{id}}", &payloads);
        assert_eq!(rendered, "https://example.com/a/42");
    }

    #[test]
    fn infers_scheme_from_absolute_target() {
        let blob = "GET https://example.com/test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let scheme = infer_default_scheme_from_request_blob(blob);
        assert_eq!(scheme, Some("https"));
    }

    #[test]
    fn infers_scheme_from_host_port() {
        let blob = "GET /test HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let scheme = infer_default_scheme_from_request_blob(blob);
        assert_eq!(scheme, Some("https"));
    }

    #[test]
    fn section_markers_replace_all_marked_parts() {
        let template = "GET /?a=§old1§&b=§old2§ HTTP/1.1\r\nHost: tld\r\n\r\n";
        let rendered = apply_section_markers(template, Some("777")).expect("render");
        assert_eq!(rendered, "GET /?a=777&b=777 HTTP/1.1\r\nHost: tld\r\n\r\n");
    }

    #[test]
    fn section_markers_require_matching_pairs() {
        let template = "GET /?a=§old HTTP/1.1\r\nHost: tld\r\n\r\n";
        let err = apply_section_markers(template, Some("x")).expect_err("must fail");
        assert!(err.to_string().contains("unmatched"));
    }

    #[test]
    fn section_markers_require_payload_value() {
        let template = "GET /?a=§old§ HTTP/1.1\r\nHost: tld\r\n\r\n";
        let err = apply_section_markers(template, None).expect_err("must fail");
        assert!(err.to_string().contains("no payload value"));
    }
}
