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



