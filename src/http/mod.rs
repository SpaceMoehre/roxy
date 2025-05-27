use url::{Position, Url};

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

#[derive(Debug)]

pub struct HttpResponse {
    status_code: u16,
    reason_phrase: String,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

impl HttpResponse {
    pub fn new(status_code: u16, reason_phrase: String, headers: Vec<(String, String)>, body: Option<String>) -> Self {
        HttpResponse {
            status_code,
            reason_phrase,
            headers,
            body,
        }
    }
    pub fn parse(response: &[u8]) -> Result<Self, String> {
        let response_str = String::from_utf8_lossy(response);
        let mut lines = response_str.lines();
        let first_line = lines.next().ok_or("Empty response")?;
        let mut parts = first_line.split_whitespace();
        let http_version = parts.next().ok_or("Missing HTTP version")?;
        let status_code = parts.next().ok_or("Missing status code")?.parse::<u16>()
            .map_err(|_| "Invalid status code")?;
        let reason_phrase = parts.skip(1).collect::<Vec<&str>>().join(" ");

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

        Ok(HttpResponse::new(status_code, reason_phrase, headers, None))
    }
    pub fn to_string(&self) -> String {
        let mut response_str = format!("HTTP/1.1 {} {}\r\n", self.status_code, self.reason_phrase);
        for (key, value) in &self.headers {
            response_str.push_str(&format!("{}: {}\r\n", key, value));
        }
        response_str.push_str("\r\n");
        if let Some(body) = &self.body {
            response_str.push_str(body);
        }
        response_str
    }
    pub fn get_header(&self, key: &str) -> Option<&String> {
        for (k, v) in &self.headers {
            if k.eq_ignore_ascii_case(key) {
                return Some(v);
            }
        }
        None
    }

}




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