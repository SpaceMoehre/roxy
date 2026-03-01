use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use roxy_core::model::CapturedExchange;
use serde::{Deserialize, Serialize};
use tantivy::{
    Index, IndexReader, ReloadPolicy,
    collector::TopDocs,
    doc,
    query::QueryParser,
    schema::{Field, STORED, STRING, Schema, TEXT, Value},
};
use tokio::sync::{Mutex, mpsc};
use tracing::{error, warn};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistorySearchHit {
    pub id: Uuid,
    pub exchange: CapturedExchange,
}

#[derive(Clone)]
pub struct StorageManager {
    inner: Arc<StorageInner>,
}

struct StorageInner {
    db: sled::Db,
    index: Index,
    index_reader: IndexReader,
    index_writer: Mutex<tantivy::IndexWriter>,
    fields: SearchFields,
}

#[derive(Clone, Copy)]
struct SearchFields {
    id: Field,
    method: Field,
    host: Field,
    uri: Field,
    request_body: Field,
    response_body: Field,
}

impl StorageManager {
    pub fn open(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_dir.as_ref();
        std::fs::create_dir_all(base_dir)
            .with_context(|| format!("failed creating storage directory {base_dir:?}"))?;

        let sled_dir = base_dir.join("sled");
        let tantivy_dir = base_dir.join("tantivy");

        std::fs::create_dir_all(&sled_dir)
            .with_context(|| format!("failed creating sled dir {sled_dir:?}"))?;
        std::fs::create_dir_all(&tantivy_dir)
            .with_context(|| format!("failed creating tantivy dir {tantivy_dir:?}"))?;

        let db = sled::open(&sled_dir).context("failed opening sled db")?;
        let (index, fields) = open_or_create_index(&tantivy_dir)?;

        let index_reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()
            .context("failed building tantivy reader")?;
        let index_writer = index
            .writer(20_000_000)
            .context("failed creating tantivy writer")?;

        Ok(Self {
            inner: Arc::new(StorageInner {
                db,
                index,
                index_reader,
                index_writer: Mutex::new(index_writer),
                fields,
            }),
        })
    }

    pub fn spawn_ingestor(
        &self,
        mut rx: mpsc::Receiver<CapturedExchange>,
    ) -> tokio::task::JoinHandle<()> {
        let manager = self.clone();
        tokio::spawn(async move {
            while let Some(exchange) = rx.recv().await {
                if let Err(err) = manager.persist_exchange(&exchange).await {
                    error!(%err, "failed persisting exchange");
                }
            }
        })
    }

    pub async fn persist_exchange(&self, exchange: &CapturedExchange) -> Result<()> {
        let id = exchange.request.id;
        let key = id.as_bytes();
        let payload = serde_json::to_vec(exchange).context("failed serializing exchange")?;
        self.inner
            .db
            .insert(key, payload)
            .context("failed writing exchange to sled")?;

        // Index the complete request/response blobs so search covers the full payloads.
        let request_blob = String::from_utf8_lossy(exchange.request.raw.as_ref()).to_string();
        let response_blob = exchange
            .response
            .as_ref()
            .map(build_response_blob_text)
            .unwrap_or_default();

        let mut writer = self.inner.index_writer.lock().await;
        writer.add_document(doc!(
            self.inner.fields.id => id.to_string(),
            self.inner.fields.method => exchange.request.method.clone(),
            self.inner.fields.host => exchange.request.host.clone(),
            self.inner.fields.uri => exchange.request.uri.clone(),
            self.inner.fields.request_body => request_blob,
            self.inner.fields.response_body => response_blob,
        ))?;
        writer.commit().context("tantivy commit failed")?;
        self.inner
            .db
            .flush()
            .context("failed flushing sled database")?;
        Ok(())
    }

    pub fn get_exchange(&self, id: Uuid) -> Result<Option<CapturedExchange>> {
        let value = self
            .inner
            .db
            .get(id.as_bytes())
            .context("sled read failed")?;

        value
            .map(|ivec| {
                serde_json::from_slice::<CapturedExchange>(&ivec)
                    .context("invalid stored exchange json")
            })
            .transpose()
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<HistorySearchHit>> {
        if query.trim().is_empty() {
            return Ok(Vec::new());
        }

        self.inner
            .index_reader
            .reload()
            .context("failed reloading tantivy reader")?;

        let searcher = self.inner.index_reader.searcher();
        let parser = QueryParser::for_index(
            &self.inner.index,
            vec![
                self.inner.fields.method,
                self.inner.fields.host,
                self.inner.fields.uri,
                self.inner.fields.request_body,
                self.inner.fields.response_body,
            ],
        );
        // Use lenient parsing for user-entered history queries so parser syntax
        // characters (for example `:` in `a:b`) do not hard-fail with 400.
        let (query, _parse_errors) = parser.parse_query_lenient(query);
        let docs = searcher
            .search(&query, &TopDocs::with_limit(limit))
            .context("tantivy search failed")?;

        let mut hits = Vec::new();
        for (_score, addr) in docs {
            let retrieved = match searcher.doc::<tantivy::schema::TantivyDocument>(addr) {
                Ok(doc) => doc,
                Err(err) => {
                    warn!(%err, "failed reading tantivy document");
                    continue;
                }
            };

            let id_value = retrieved
                .get_first(self.inner.fields.id)
                .and_then(|v| v.as_str())
                .and_then(|v| Uuid::parse_str(v).ok());

            let Some(id) = id_value else {
                continue;
            };

            if let Some(exchange) = self.get_exchange(id)? {
                hits.push(HistorySearchHit { id, exchange });
            }
        }

        Ok(hits)
    }

    pub fn list_recent(&self, limit: usize) -> Result<Vec<HistorySearchHit>> {
        let mut rows = Vec::new();
        for row in self.inner.db.iter() {
            let (_, value) = row.context("sled iteration failed")?;
            let exchange = serde_json::from_slice::<CapturedExchange>(&value)
                .context("invalid stored exchange json")?;
            rows.push(HistorySearchHit {
                id: exchange.request.id,
                exchange,
            });
        }

        rows.sort_by(|a, b| {
            b.exchange
                .request
                .created_at_unix_ms
                .cmp(&a.exchange.request.created_at_unix_ms)
        });
        rows.truncate(limit);
        Ok(rows)
    }
}

fn build_response_blob_text(response: &roxy_core::model::CapturedResponse) -> String {
    let mut blob = format!("HTTP/1.1 {}\r\n", response.status);
    for header in &response.headers {
        blob.push_str(&header.name);
        blob.push_str(": ");
        blob.push_str(&header.value);
        blob.push_str("\r\n");
    }
    blob.push_str("\r\n");
    blob.push_str(&String::from_utf8_lossy(response.body.as_ref()));
    blob
}

fn open_or_create_index(path: &Path) -> Result<(Index, SearchFields)> {
    let mut schema_builder = Schema::builder();
    let _id = schema_builder.add_text_field("id", STRING | STORED);
    let _method = schema_builder.add_text_field("method", STRING | STORED);
    let _host = schema_builder.add_text_field("host", STRING | STORED);
    let _uri = schema_builder.add_text_field("uri", TEXT | STORED);
    let _request_body = schema_builder.add_text_field("request_body", TEXT);
    let _response_body = schema_builder.add_text_field("response_body", TEXT);
    let schema = schema_builder.build();

    let index = match Index::open_in_dir(path) {
        Ok(existing) => existing,
        Err(_) => Index::create_in_dir(path, schema).context("failed creating tantivy index")?,
    };

    let schema = index.schema();
    let fields = SearchFields {
        id: schema.get_field("id").expect("id field exists"),
        method: schema.get_field("method").expect("method field exists"),
        host: schema.get_field("host").expect("host field exists"),
        uri: schema.get_field("uri").expect("uri field exists"),
        request_body: schema
            .get_field("request_body")
            .expect("request_body field exists"),
        response_body: schema
            .get_field("response_body")
            .expect("response_body field exists"),
    };

    Ok((index, fields))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use tempfile::TempDir;

    use super::*;
    use roxy_core::model::{CapturedRequest, CapturedResponse, HeaderValuePair, now_unix_ms};

    fn fake_exchange() -> CapturedExchange {
        let id = Uuid::new_v4();
        CapturedExchange {
            request: CapturedRequest {
                id,
                created_at_unix_ms: now_unix_ms(),
                method: "POST".to_string(),
                uri: "http://example.com/login".to_string(),
                host: "example.com".to_string(),
                headers: vec![HeaderValuePair {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                }],
                body: Bytes::from_static(br#"{"user":"admin"}"#),
                raw: Bytes::from_static(
                    b"POST http://example.com/login HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\n\r\n{\"user\":\"admin\"}",
                ),
            },
            response: Some(CapturedResponse {
                request_id: id,
                created_at_unix_ms: now_unix_ms(),
                status: 200,
                headers: vec![],
                body: Bytes::from_static(br#"{"ok":true}"#),
            }),
            duration_ms: 20,
            error: None,
        }
    }

    #[tokio::test]
    async fn stores_and_searches_exchange() {
        let tmp = TempDir::new().expect("tmp");
        let manager = StorageManager::open(tmp.path()).expect("storage");
        let exchange = fake_exchange();

        manager
            .persist_exchange(&exchange)
            .await
            .expect("persist exchange");

        let hits = manager.search("login", 10).expect("search");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].exchange.request.uri, "http://example.com/login");
    }

    #[tokio::test]
    async fn lists_recent_exchanges() {
        let tmp = TempDir::new().expect("tmp");
        let manager = StorageManager::open(tmp.path()).expect("storage");

        let mut first = fake_exchange();
        first.request.created_at_unix_ms = 1;
        let mut second = fake_exchange();
        second.request.created_at_unix_ms = 2;

        manager
            .persist_exchange(&first)
            .await
            .expect("persist first");
        manager
            .persist_exchange(&second)
            .await
            .expect("persist second");

        let rows = manager.list_recent(10).expect("recent");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].exchange.request.created_at_unix_ms, 2);
        assert_eq!(rows[1].exchange.request.created_at_unix_ms, 1);
    }

    #[tokio::test]
    async fn search_allows_colon_in_literal_query() {
        let tmp = TempDir::new().expect("tmp");
        let manager = StorageManager::open(tmp.path()).expect("storage");
        let exchange = fake_exchange();

        manager
            .persist_exchange(&exchange)
            .await
            .expect("persist exchange");

        let hits = manager.search("a:b", 10).expect("search should not fail");
        assert!(hits.is_empty());
    }

    #[tokio::test]
    async fn search_indexes_full_request_and_response_blobs() {
        let tmp = TempDir::new().expect("tmp");
        let manager = StorageManager::open(tmp.path()).expect("storage");
        let id = Uuid::new_v4();
        let exchange = CapturedExchange {
            request: CapturedRequest {
                id,
                created_at_unix_ms: now_unix_ms(),
                method: "GET".to_string(),
                uri: "http://example.com/blob".to_string(),
                host: "example.com".to_string(),
                headers: vec![HeaderValuePair {
                    name: "x-request-token".to_string(),
                    value: "req-blob-42".to_string(),
                }],
                body: Bytes::from_static(b"request-body-data"),
                raw: Bytes::from_static(
                    b"GET http://example.com/blob HTTP/1.1\r\nhost: example.com\r\nx-request-token: req-blob-42\r\n\r\nrequest-body-data",
                ),
            },
            response: Some(CapturedResponse {
                request_id: id,
                created_at_unix_ms: now_unix_ms(),
                status: 418,
                headers: vec![HeaderValuePair {
                    name: "x-response-token".to_string(),
                    value: "resp-blob-84".to_string(),
                }],
                body: Bytes::from_static(b"response-body-data"),
            }),
            duration_ms: 7,
            error: None,
        };

        manager
            .persist_exchange(&exchange)
            .await
            .expect("persist exchange");

        let request_hits = manager.search("req-blob-42", 10).expect("request blob search");
        assert_eq!(request_hits.len(), 1);
        assert_eq!(request_hits[0].id, id);

        let response_header_hits = manager
            .search("resp-blob-84", 10)
            .expect("response header blob search");
        assert_eq!(response_header_hits.len(), 1);
        assert_eq!(response_header_hits[0].id, id);

        let response_status_hits = manager.search("418", 10).expect("response status search");
        assert_eq!(response_status_hits.len(), 1);
        assert_eq!(response_status_hits[0].id, id);

        let response_body_hits = manager
            .search("response-body-data", 10)
            .expect("response body blob search");
        assert_eq!(response_body_hits.len(), 1);
        assert_eq!(response_body_hits[0].id, id);
    }
}
