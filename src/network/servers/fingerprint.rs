use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);
const READ_TIMEOUT: Duration = Duration::from_millis(500);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum bytes to read from a banner or HTTP response.
const MAX_READ: usize = 8192;

/// Ports at or above this threshold are ephemeral and skipped.
const EPHEMERAL_PORT_MIN: u16 = 49153;

/// Result of probing a single listening port.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub banner: Option<String>,
    pub http_server: Option<String>,
    pub http_powered_by: Option<String>,
    pub http_title: Option<String>,
    pub http_headers: Vec<(String, String)>,
    pub tls_detected: bool,
    pub is_responsive: bool,
}

/// Intermediate struct for parsed HTTP responses.
struct HttpInfo {
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub title: Option<String>,
    pub headers: Vec<(String, String)>,
}

/// Probe multiple ports in parallel. Returns map of port -> ProbeResult.
/// Only probes TCP ports (UDP probing is unreliable).
pub fn probe_ports(ports: &[(u16, IpAddr)]) -> HashMap<u16, ProbeResult> {
    let results: HashMap<u16, ProbeResult> = std::thread::scope(|s| {
        let handles: Vec<_> = ports
            .iter()
            .filter(|(port, _)| *port < EPHEMERAL_PORT_MIN)
            .map(|(port, addr)| {
                let port = *port;
                let addr = *addr;
                s.spawn(move || (port, probe_single(addr, port)))
            })
            .collect();

        let mut map = HashMap::new();
        for handle in handles {
            if let Ok((port, Some(result))) = handle.join() {
                map.insert(port, result);
            }
        }
        map
    });

    results
}

/// Probe a single TCP port. Returns None if connection fails.
fn probe_single(addr: IpAddr, port: u16) -> Option<ProbeResult> {
    // If the bind address is unspecified (0.0.0.0 or ::), connect to localhost instead.
    let connect_addr = match addr {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        other => other,
    };
    let sock_addr = SocketAddr::new(connect_addr, port);

    // 1. Connect with timeout
    let mut stream = TcpStream::connect_timeout(&sock_addr, CONNECT_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(READ_TIMEOUT)).ok();
    stream.set_write_timeout(Some(CONNECT_TIMEOUT)).ok();
    stream.set_nodelay(true).ok();

    let mut result = ProbeResult {
        banner: None,
        http_server: None,
        http_powered_by: None,
        http_title: None,
        http_headers: Vec::new(),
        tls_detected: false,
        is_responsive: false,
    };

    // 2. Try raw read first — catches SSH, SMTP, FTP, MySQL banners
    let mut buf = [0u8; MAX_READ];
    let banner_bytes = match stream.read(&mut buf) {
        Ok(0) => None,
        Ok(n) => Some(buf[..n].to_vec()),
        Err(_) => None,
    };

    if let Some(ref raw) = banner_bytes {
        result.is_responsive = true;

        // Check for TLS handshake/alert bytes
        if !raw.is_empty() && (raw[0] == 0x15 || raw[0] == 0x16) {
            result.tls_detected = true;
            // TLS detected — we cannot proceed further without a TLS handshake.
            // Mark as responsive and return what we know.
            return Some(result);
        }

        // Check MySQL protocol: byte[4] == 0x0a means protocol version 10
        if raw.len() > 4 && raw[4] == 0x0a {
            // Likely MySQL greeting packet. The banner starts after the packet header.
            if let Some(banner_str) = extract_printable(raw) {
                result.banner = Some(format!("MySQL: {}", banner_str));
            } else {
                result.banner = Some("MySQL".to_string());
            }
            return Some(result);
        }

        // Try to interpret as UTF-8 for text-based protocols
        if let Ok(text) = std::str::from_utf8(raw) {
            let trimmed = text.trim();

            // SSH banner
            if trimmed.starts_with("SSH-") {
                result.banner = Some(trimmed.lines().next().unwrap_or(trimmed).to_string());
                return Some(result);
            }

            // SMTP greeting
            if trimmed.starts_with("220 ") || trimmed.starts_with("220-") {
                result.banner = Some(trimmed.lines().next().unwrap_or(trimmed).to_string());
                return Some(result);
            }

            // FTP greeting (220 or 230)
            if trimmed.starts_with("230 ") || trimmed.starts_with("230-") {
                result.banner = Some(trimmed.lines().next().unwrap_or(trimmed).to_string());
                return Some(result);
            }

            // Check if we got an HTTP response spontaneously (unlikely but possible)
            if trimmed.starts_with("HTTP/") {
                if let Some(info) = parse_http_response(raw) {
                    apply_http_info(&mut result, info);
                    result.banner =
                        Some(trimmed.lines().next().unwrap_or(trimmed).to_string());
                    return Some(result);
                }
            }
        }

        // If we got binary data that isn't MySQL or TLS, store as hex snippet
        if result.banner.is_none() {
            if let Some(printable) = extract_printable(raw) {
                result.banner = Some(printable);
            }
        }
    }

    // 3. Try Redis PING before HTTP — Redis responds immediately
    if banner_bytes.is_none() && is_likely_redis_port(port) {
        if let Some(redis_result) = try_redis_ping(addr, port) {
            return Some(redis_result);
        }
    }

    // 4. If no banner received OR first bytes didn't identify a protocol,
    //    try sending an HTTP GET request.
    let should_try_http = banner_bytes.is_none()
        || banner_bytes
            .as_ref()
            .map(|b| looks_like_needs_http(b))
            .unwrap_or(false);

    if should_try_http {
        // Need a fresh connection for HTTP since the old stream may be in a bad state
        if let Ok(mut http_stream) = TcpStream::connect_timeout(&sock_addr, CONNECT_TIMEOUT) {
            http_stream.set_read_timeout(Some(HTTP_READ_TIMEOUT)).ok();
            http_stream.set_write_timeout(Some(CONNECT_TIMEOUT)).ok();
            http_stream.set_nodelay(true).ok();

            let host = match addr {
                IpAddr::V4(v4) => v4.to_string(),
                IpAddr::V6(v6) => format!("[{}]", v6),
            };

            let request = format!(
                "GET / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\nUser-Agent: psnet/1.0\r\n\r\n",
                host
            );

            if http_stream.write_all(request.as_bytes()).is_ok() {
                let mut response = Vec::with_capacity(MAX_READ);
                let mut chunk = [0u8; 4096];

                // Read until EOF or MAX_READ
                loop {
                    match http_stream.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            response.extend_from_slice(&chunk[..n]);
                            if response.len() >= MAX_READ {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }

                if !response.is_empty() {
                    result.is_responsive = true;

                    // Check for TLS response to our plaintext HTTP
                    if response[0] == 0x15 || response[0] == 0x16 {
                        result.tls_detected = true;
                        return Some(result);
                    }

                    if let Some(info) = parse_http_response(&response) {
                        apply_http_info(&mut result, info);
                    }

                    if result.banner.is_none() {
                        if let Ok(text) = std::str::from_utf8(&response) {
                            let first_line = text.lines().next().unwrap_or("").to_string();
                            if !first_line.is_empty() {
                                result.banner = Some(first_line);
                            }
                        }
                    }
                }
            }
        }
    }

    if result.is_responsive
        || result.banner.is_some()
        || result.http_server.is_some()
        || result.tls_detected
    {
        Some(result)
    } else {
        // Port accepted connection but gave us nothing — still counts as responsive
        result.is_responsive = true;
        Some(result)
    }
}

/// Parse HTTP response: extract status, headers, title.
fn parse_http_response(data: &[u8]) -> Option<HttpInfo> {
    let text = std::str::from_utf8(data).ok().or_else(|| {
        // Try lossy conversion for responses with binary body but ASCII headers
        None
    })?;

    // Must start with HTTP/
    if !text.starts_with("HTTP/") {
        // Try lossy parse
        return parse_http_response_lossy(data);
    }

    parse_http_text(text)
}

/// Parse HTTP from a text string.
fn parse_http_text(text: &str) -> Option<HttpInfo> {
    // Split headers from body at \r\n\r\n
    let (header_section, body) = if let Some(pos) = text.find("\r\n\r\n") {
        (&text[..pos], &text[pos + 4..])
    } else if let Some(pos) = text.find("\n\n") {
        (&text[..pos], &text[pos + 2..])
    } else {
        (text, "")
    };

    let mut lines = header_section.lines();

    // First line must be status line
    let status_line = lines.next()?;
    if !status_line.starts_with("HTTP/") {
        return None;
    }

    let mut server = None;
    let mut powered_by = None;
    let mut content_type = None;
    let mut interesting_headers = Vec::new();

    // Headers we consider interesting
    const INTERESTING: &[&str] = &[
        "server",
        "x-powered-by",
        "x-framework",
        "via",
        "content-type",
        "x-aspnet-version",
        "x-generator",
        "x-drupal-cache",
        "x-varnish",
        "x-cache",
        "x-runtime",
        "x-request-id",
    ];

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            break;
        }

        if let Some((name, value)) = line.split_once(':') {
            let name_trimmed = name.trim();
            let value_trimmed = value.trim();
            let name_lower = name_trimmed.to_lowercase();

            match name_lower.as_str() {
                "server" => server = Some(value_trimmed.to_string()),
                "x-powered-by" => powered_by = Some(value_trimmed.to_string()),
                "content-type" => content_type = Some(value_trimmed.to_string()),
                _ => {}
            }

            if INTERESTING.contains(&name_lower.as_str()) {
                interesting_headers
                    .push((name_trimmed.to_string(), value_trimmed.to_string()));
            }
        }
    }

    // Extract <title> from body if Content-Type is text/html
    let title = if content_type
        .as_ref()
        .map(|ct| ct.contains("text/html"))
        .unwrap_or(false)
    {
        extract_html_title(body)
    } else {
        None
    };

    Some(HttpInfo {
        server,
        powered_by,
        title,
        headers: interesting_headers,
    })
}

/// Try parsing HTTP response using lossy UTF-8 conversion (for binary bodies with ASCII headers).
fn parse_http_response_lossy(data: &[u8]) -> Option<HttpInfo> {
    // Find the header/body boundary in raw bytes
    let header_end = find_header_end(data)?;
    let header_bytes = &data[..header_end];

    // Headers should be valid ASCII/UTF-8
    let header_text = std::str::from_utf8(header_bytes).ok()?;
    if !header_text.starts_with("HTTP/") {
        return None;
    }

    // Get body as lossy string for title extraction
    let body_start = header_end + 4; // skip \r\n\r\n
    let body = if body_start < data.len() {
        String::from_utf8_lossy(&data[body_start..])
    } else {
        std::borrow::Cow::Borrowed("")
    };

    let mut lines = header_text.lines();
    let status_line = lines.next()?;
    if !status_line.starts_with("HTTP/") {
        return None;
    }

    let mut server = None;
    let mut powered_by = None;
    let mut content_type = None;
    let mut interesting_headers = Vec::new();

    const INTERESTING: &[&str] = &[
        "server",
        "x-powered-by",
        "x-framework",
        "via",
        "content-type",
        "x-aspnet-version",
        "x-generator",
        "x-drupal-cache",
        "x-varnish",
        "x-cache",
        "x-runtime",
        "x-request-id",
    ];

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let name_trimmed = name.trim();
            let value_trimmed = value.trim();
            let name_lower = name_trimmed.to_lowercase();

            match name_lower.as_str() {
                "server" => server = Some(value_trimmed.to_string()),
                "x-powered-by" => powered_by = Some(value_trimmed.to_string()),
                "content-type" => content_type = Some(value_trimmed.to_string()),
                _ => {}
            }

            if INTERESTING.contains(&name_lower.as_str()) {
                interesting_headers
                    .push((name_trimmed.to_string(), value_trimmed.to_string()));
            }
        }
    }

    let title = if content_type
        .as_ref()
        .map(|ct| ct.contains("text/html"))
        .unwrap_or(false)
    {
        extract_html_title(&body)
    } else {
        None
    };

    Some(HttpInfo {
        server,
        powered_by,
        title,
        headers: interesting_headers,
    })
}

/// Find `\r\n\r\n` boundary in raw bytes. Returns the index of the first `\r` in the sequence.
fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4)
        .position(|w| w == b"\r\n\r\n")
}

/// Extract <title>...</title> from HTML body (case-insensitive).
fn extract_html_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();

    let start_tag = "<title";
    let start = lower.find(start_tag)?;

    // Find the end of the opening tag (handle <title> or <title attr="">)
    let tag_close = lower[start..].find('>')?;
    let content_start = start + tag_close + 1;

    let end_tag = "</title>";
    let content_end_rel = lower[content_start..].find(end_tag)?;
    let content_end = content_start + content_end_rel;

    if content_end <= content_start {
        return None;
    }

    let title = body[content_start..content_end].trim();
    if title.is_empty() {
        None
    } else {
        // Decode basic HTML entities
        let decoded = title
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&apos;", "'");
        Some(decoded)
    }
}

/// Try to connect and send Redis PING. Returns a ProbeResult if Redis responds.
fn try_redis_ping(addr: IpAddr, port: u16) -> Option<ProbeResult> {
    let sock_addr = SocketAddr::new(addr, port);
    let mut stream = TcpStream::connect_timeout(&sock_addr, CONNECT_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(READ_TIMEOUT)).ok();
    stream.set_write_timeout(Some(CONNECT_TIMEOUT)).ok();
    stream.set_nodelay(true).ok();

    stream.write_all(b"PING\r\n").ok()?;

    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }

    let response = std::str::from_utf8(&buf[..n]).ok()?;
    if response.trim().starts_with("+PONG") {
        Some(ProbeResult {
            banner: Some("Redis".to_string()),
            http_server: None,
            http_powered_by: None,
            http_title: None,
            http_headers: Vec::new(),
            tls_detected: false,
            is_responsive: true,
        })
    } else if response.starts_with("-") {
        // Redis error response (e.g., -NOAUTH) — still Redis
        let msg = response.trim().trim_start_matches('-');
        Some(ProbeResult {
            banner: Some(format!("Redis ({})", msg.lines().next().unwrap_or("auth required"))),
            http_server: None,
            http_powered_by: None,
            http_title: None,
            http_headers: Vec::new(),
            tls_detected: false,
            is_responsive: true,
        })
    } else {
        None
    }
}

/// Check if a port is commonly associated with Redis.
fn is_likely_redis_port(port: u16) -> bool {
    port == 6379 || port == 6380 || port == 6381
}

/// Check if raw bytes suggest we need to send an HTTP request to get useful info.
/// Returns true if we got nothing recognizable from the initial read.
fn looks_like_needs_http(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }

    // If it starts with TLS bytes, don't send HTTP
    if data[0] == 0x15 || data[0] == 0x16 {
        return false;
    }

    // If we already got an HTTP response, no need
    if data.len() >= 5 && &data[..5] == b"HTTP/" {
        return false;
    }

    // If it's a known text protocol banner, no need for HTTP
    if let Ok(text) = std::str::from_utf8(data) {
        let trimmed = text.trim();
        if trimmed.starts_with("SSH-")
            || trimmed.starts_with("220 ")
            || trimmed.starts_with("220-")
            || trimmed.starts_with("230 ")
            || trimmed.starts_with("230-")
            || trimmed.starts_with("+PONG")
        {
            return false;
        }
    }

    // Check for MySQL greeting
    if data.len() > 4 && data[4] == 0x0a {
        return false;
    }

    // Unknown data — might be a partial response or something else.
    // If the port is a common HTTP port, try HTTP anyway.
    true
}

/// Extract printable ASCII from raw bytes, truncating to a reasonable length.
fn extract_printable(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    let mut result = String::with_capacity(128);
    for &b in data.iter().take(128) {
        if b >= 0x20 && b < 0x7f {
            result.push(b as char);
        } else if b == b'\r' || b == b'\n' || b == b'\t' {
            result.push(' ');
        }
        // Skip non-printable bytes
    }

    let trimmed = result.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Apply parsed HTTP info onto a ProbeResult.
fn apply_http_info(result: &mut ProbeResult, info: HttpInfo) {
    result.http_server = info.server;
    result.http_powered_by = info.powered_by;
    result.http_title = info.title;
    result.http_headers = info.headers;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_response_basic() {
        let response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nX-Powered-By: PHP/7.4\r\n\r\n<html><head><title>Test Page</title></head><body></body></html>";
        let info = parse_http_response(response).unwrap();
        assert_eq!(info.server, Some("nginx/1.18.0".to_string()));
        assert_eq!(info.powered_by, Some("PHP/7.4".to_string()));
        assert_eq!(info.title, Some("Test Page".to_string()));
        assert!(info.headers.len() >= 3);
    }

    #[test]
    fn test_parse_http_response_no_title() {
        let response = b"HTTP/1.1 200 OK\r\nServer: Apache\r\nContent-Type: application/json\r\n\r\n{\"ok\":true}";
        let info = parse_http_response(response).unwrap();
        assert_eq!(info.server, Some("Apache".to_string()));
        assert_eq!(info.title, None);
    }

    #[test]
    fn test_parse_http_response_not_http() {
        let response = b"SSH-2.0-OpenSSH_8.9\r\n";
        assert!(parse_http_response(response).is_none());
    }

    #[test]
    fn test_extract_html_title() {
        assert_eq!(
            extract_html_title("<html><head><title>Hello World</title></head></html>"),
            Some("Hello World".to_string())
        );
        assert_eq!(
            extract_html_title("<html><head><TITLE>Case Test</TITLE></head></html>"),
            Some("Case Test".to_string())
        );
        assert_eq!(
            extract_html_title("<html><head></head></html>"),
            None
        );
        assert_eq!(
            extract_html_title("<title>A &amp; B</title>"),
            Some("A & B".to_string())
        );
    }

    #[test]
    fn test_extract_printable() {
        assert_eq!(
            extract_printable(b"Hello\x00World"),
            Some("HelloWorld".to_string())
        );
        assert_eq!(extract_printable(b"\x00\x01\x02"), None);
        assert_eq!(
            extract_printable(b"SSH-2.0-OpenSSH\r\n"),
            Some("SSH-2.0-OpenSSH".to_string())
        );
    }

    #[test]
    fn test_looks_like_needs_http() {
        assert!(looks_like_needs_http(b""));
        assert!(!looks_like_needs_http(b"\x16\x03\x01"));
        assert!(!looks_like_needs_http(b"HTTP/1.1 200 OK"));
        assert!(!looks_like_needs_http(b"SSH-2.0-OpenSSH"));
        assert!(looks_like_needs_http(b"some random data"));
    }

    #[test]
    fn test_probe_ports_empty() {
        let result = probe_ports(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_ephemeral_ports_skipped() {
        // Ephemeral ports should be skipped entirely
        let result = probe_ports(&[(50000, IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))]);
        assert!(result.is_empty());
    }
}
