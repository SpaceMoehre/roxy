//! Async middleware trait for the proxy engine.
//!
//! The [`ProxyMiddleware`] trait provides two hook points that the
//! [`ProxyEngine`](crate::proxy::ProxyEngine) calls during every HTTP
//! exchange:
//!
//! 1. **[`on_request_pre_capture`](ProxyMiddleware::on_request_pre_capture)** —
//!    invoked after the raw request bytes are read from the client but before
//!    the request is persisted or forwarded upstream. Implementations may
//!    inspect or mutate headers, body, and the raw blob.
//!
//! 2. **[`on_response_pre_capture`](ProxyMiddleware::on_response_pre_capture)** —
//!    invoked after the upstream response is received but before it is persisted
//!    or delivered back to the client. The original request is also available
//!    for correlation.
//!
//! Both methods have default no-op implementations, so consumers can override
//! only the hooks they need. The `roxy-app` binary supplies a
//! `PluginBridgeMiddleware` that delegates these hooks to the Python plugin
//! system.

use anyhow::Result;
use async_trait::async_trait;

use crate::model::{CapturedRequest, CapturedResponse};

/// Async hook point that the proxy engine calls around every HTTP exchange.
///
/// Implementations must be cheaply [`Clone`]-able (typically wrapping
/// shared state in `Arc`) and safe to invoke from multiple concurrent tasks
/// (`Send + Sync`).
///
/// Both methods have default no-op implementations that pass the value
/// through unchanged.
///
/// # Errors
///
/// Returning an error from either hook causes the engine to log the failure
/// and continue with the original (un-mutated) request or response.
#[async_trait]
pub trait ProxyMiddleware: Send + Sync {
    /// Called after the downstream request is assembled but before it is
    /// forwarded upstream or enqueued for interception.
    ///
    /// Return the (possibly mutated) [`CapturedRequest`] to continue the
    /// exchange, or an error to skip the mutation.
    async fn on_request_pre_capture(&self, request: CapturedRequest) -> Result<CapturedRequest> {
        Ok(request)
    }

    /// Called after the upstream response is received but before it is
    /// persisted or returned to the downstream client.
    ///
    /// `_request` is the captured request that triggered this response and
    /// can be used for correlation or conditional logic.
    async fn on_response_pre_capture(
        &self,
        _request: &CapturedRequest,
        response: CapturedResponse,
    ) -> Result<CapturedResponse> {
        Ok(response)
    }
}
