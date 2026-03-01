use anyhow::Result;
use async_trait::async_trait;

use crate::model::{CapturedRequest, CapturedResponse};

#[async_trait]
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
