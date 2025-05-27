
pub mod httprequest;
pub mod httpresponse;

#[derive(Debug)]
pub struct RawRequest {
    data: String
}

impl RawRequest {
    pub fn new(data: String) -> Self {
        RawRequest { data }
    }
    pub fn parse(request: &[u8]) -> Result<Self, String> {
        let request_str = String::from_utf8_lossy(request).to_string();
        Ok(RawRequest::new(request_str))
    }
    pub fn to_string(&self) -> String {
        self.data.clone()
    }
}


