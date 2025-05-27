use url::{Position, Url};

#[derive(Debug)]
pub struct HttpRequest {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

impl HttpRequest {
    pub fn new(method: String, url: String, headers: Vec<(String, String)>, body: Option<String>) -> Self {
        HttpRequest {
            method,
            url,
            headers,
            body,
        }
    }
    pub fn parse(request: &[u8]) -> Result<Self, String> {
        let request_str = String::from_utf8_lossy(request);
        let mut lines = request_str.lines();
        let first_line = lines.next().ok_or("Empty request")?;
        let mut parts = first_line.split_whitespace();
        let method = parts.next().ok_or("Missing method")?.to_string();
        let url = parts.next().ok_or("Missing URL")?.to_string();

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let mut header_parts = line.splitn(2, ':');
            let key = header_parts.next().ok_or("Missing header key")?.trim().to_string();
            let value = header_parts.next().ok_or("Missing header value")?.trim().to_string();
            headers.push((key, value));
        }

        Ok(HttpRequest::new(method, url, headers, None))
    }
    pub fn to_string(&self) -> String {
        let mut request_str = format!("{} {} HTTP/1.1\r\n", self.method, self.url);
        for (key, value) in &self.headers {
            request_str.push_str(&format!("{}: {}\r\n", key, value));
        }
        request_str.push_str("\r\n");
        if let Some(body) = &self.body {
            request_str.push_str(body);
        }
        request_str
    }
    pub fn get_header(&self, key: &str) -> Option<&String> {
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case(key) {
                return Some(v);
            }
        }
        None
    }
    pub fn set_header(&mut self, key: String, value: String) {
        for (k, v) in &mut self.headers {
            if k.eq_ignore_ascii_case(&key) {
                *v = value;
                return;
            }
        }
        self.headers.push((key, value));
    }
    pub fn remove_header(&mut self, key: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
    }
    pub fn get_body(&self) -> Option<&String> {
        self.body.as_ref()
    }
    pub fn set_body(&mut self, body: String) {
        self.body = Some(body);
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }
    pub fn get_method(&self) -> &String {
        &self.method
    }
    pub fn replace_proxy_uri(&mut self) -> Result<(), String> {
        let url = Url::parse(&self.url).unwrap()[Position::BeforePath..].to_string();
        println!("{}",url);
        //self.url = &url[Position::BeforePath..];
        self.url = url;
        Ok(())
    }
}