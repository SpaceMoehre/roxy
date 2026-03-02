//! roxy_core `middleware` module.
//!
//! Exposes public types and functions used by the `roxy` runtime and API surface.

use anyhow::Result;
use async_trait::async_trait;

use crate::model::{CapturedRequest, CapturedResponse};

#[async_trait]
/// Defines behavior for `ProxyMiddleware` implementations.
///
/// See also: [`ProxyMiddleware`].
pub trait ProxyMiddleware: Send + Sync {
    async fn on_request_pre_capture(&self, request: CapturedRequest) -> Result<CapturedRequest> {
        Ok(request)
    }

    async fn on_response_pre_capture(
        &self,
        _request: &CapturedRequest,
        response: CapturedResponse,
    ) -> Result<CapturedResponse> {
        Ok(response)
    }
}
