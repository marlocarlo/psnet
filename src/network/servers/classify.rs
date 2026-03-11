use super::fingerprint::ProbeResult;
use super::fingerprints;
use super::types::ServerKind;

// Re-export for convenience — callers can use `classify::ProcessInfo` if needed.
#[allow(unused_imports)]
use super::listeners::ProcessInfo;

// ─── Scoring weights ─────────────────────────────────────────────────────────

const SCORE_PROCESS: u32 = 40;
const SCORE_EXE_PATH: u32 = 30;
const SCORE_CMDLINE: u32 = 50;
const SCORE_HTTP_SERVER: u32 = 35;
const SCORE_HTTP_POWERED: u32 = 30;
const SCORE_HTTP_HEADER: u32 = 25;
const SCORE_HTML_TITLE: u32 = 20;
const SCORE_BANNER_STARTS: u32 = 45;
const SCORE_BANNER_CONTAINS: u32 = 25;
const SCORE_PORT: u32 = 5;

// ─── Main classification entry point ─────────────────────────────────────────

/// Classify a listening port into a `ServerKind` based on all available signals.
/// Uses a scoring system across the fingerprint database: process name, exe path,
/// command line, HTTP headers, banners, and default ports.
///
/// Returns `(kind, version_string)`.
pub fn classify(
    process_name: &str,
    exe_path: &str,
    cmdline: &str,
    port: u16,
    probe: Option<&ProbeResult>,
) -> (ServerKind, Option<String>) {
    let proc_lower = process_name.to_lowercase();
    let proc_stem = proc_lower.strip_suffix(".exe").unwrap_or(&proc_lower);
    let exe_lower = exe_path.to_lowercase();
    let cmd_lower = cmdline.to_lowercase();

    // Pre-extract probe fields for matching.
    let http_server_lower = probe
        .and_then(|p| p.http_server.as_ref())
        .map(|s| s.to_lowercase());
    let http_powered_lower = probe
        .and_then(|p| p.http_powered_by.as_ref())
        .map(|s| s.to_lowercase());
    let http_title_lower = probe
        .and_then(|p| p.http_title.as_ref())
        .map(|s| s.to_lowercase());
    let banner = probe.and_then(|p| p.banner.as_deref());
    let banner_lower = banner.map(|b| b.to_lowercase());

    let db = fingerprints::fingerprints();

    let mut best_score: u32 = 0;
    let mut best_idx: Option<usize> = None;

    for (i, fp) in db.iter().enumerate() {
        let mut score: u32 = 0;

        // ── Process name match ──
        if !fp.process_names.is_empty()
            && fp.process_names.iter().any(|pn| pn == proc_stem)
        {
            score += SCORE_PROCESS;
        }

        // ── Exe path match ──
        if !fp.exe_path_contains.is_empty()
            && fp.exe_path_contains.iter().any(|ep| exe_lower.contains(ep.as_str()))
        {
            score += SCORE_EXE_PATH;
        }

        // ── Cmdline match (ANY pattern) ──
        if !fp.cmdline_contains.is_empty() {
            let cmdline_allowed = if fp.cmdline_requires_process.is_empty() {
                true
            } else {
                fp.cmdline_requires_process.iter().any(|rp| rp == proc_stem)
            };
            if cmdline_allowed
                && fp.cmdline_contains.iter().any(|pat| cmd_lower.contains(pat.as_str()))
            {
                score += SCORE_CMDLINE;
            }
        }

        // ── HTTP Server header match ──
        if !fp.http_server_contains.is_empty() {
            if let Some(ref srv) = http_server_lower {
                if fp.http_server_contains.iter().any(|pat| srv.contains(pat.as_str())) {
                    score += SCORE_HTTP_SERVER;
                }
            }
        }

        // ── HTTP Powered-By match ──
        if !fp.http_powered_by_contains.is_empty() {
            if let Some(ref pw) = http_powered_lower {
                if fp.http_powered_by_contains.iter().any(|pat| pw.contains(pat.as_str())) {
                    score += SCORE_HTTP_POWERED;
                }
            }
        }

        // ── HTTP header match ──
        if !fp.http_header_contains.is_empty() {
            if let Some(pr) = probe {
                let matched = fp.http_header_contains.iter().any(|(hname, hval)| {
                    pr.http_headers.iter().any(|(k, v)| {
                        let kl = k.to_lowercase();
                        let vl = v.to_lowercase();
                        kl.contains(hname.as_str())
                            && (hval.is_empty() || vl.contains(hval.as_str()))
                    })
                });
                if matched {
                    score += SCORE_HTTP_HEADER;
                }
            }
        }

        // ── HTML title match ──
        if !fp.html_title_contains.is_empty() {
            if let Some(ref title) = http_title_lower {
                if fp.html_title_contains.iter().any(|pat| title.contains(pat.as_str())) {
                    score += SCORE_HTML_TITLE;
                }
            }
        }

        // ── Banner starts_with match ──
        if !fp.banner_starts_with.is_empty() {
            if let Some(b) = banner {
                if fp.banner_starts_with.iter().any(|pat| b.starts_with(pat.as_str())) {
                    score += SCORE_BANNER_STARTS;
                }
            }
        }

        // ── Banner contains match ──
        if !fp.banner_contains.is_empty() {
            if let Some(ref bl) = banner_lower {
                if fp.banner_contains.iter().any(|pat| bl.contains(pat.as_str())) {
                    score += SCORE_BANNER_CONTAINS;
                }
            }
        }

        // ── Default port match ──
        if !fp.default_ports.is_empty() && fp.default_ports.contains(&port) {
            score += SCORE_PORT;
        }

        if score == 0 {
            continue;
        }

        // Tie-break: prefer lower priority value (higher specificity).
        if score > best_score
            || (score == best_score
                && best_idx
                    .map(|bi| fp.priority < db[bi].priority)
                    .unwrap_or(true))
        {
            best_score = score;
            best_idx = Some(i);
        }
    }

    // Require a minimum score threshold. Port-only matches (score == 5) are
    // never trusted — any port can be used by any application. We need at least
    // one strong signal (process, banner, HTTP header) or two weaker signals.
    // Minimum: SCORE_PORT + one real signal, i.e. > SCORE_PORT.
    let fp = match best_idx {
        Some(i) if best_score > SCORE_PORT => &db[i],
        _ => return (ServerKind::Unknown, None),
    };

    let kind = fp.kind.clone();

    // ── Version extraction ──
    let version = extract_version_for_match(fp, probe, banner);

    (kind, version)
}

/// Attempt to extract a version string using the matched fingerprint's hints
/// plus generic banner extraction.
fn extract_version_for_match(
    fp: &super::fingerprints::TechFingerprint,
    probe: Option<&ProbeResult>,
    banner: Option<&str>,
) -> Option<String> {
    // Try version_from_header_prefix against the Server header.
    if let Some(ref prefix) = fp.version_from_header_prefix {
        if let Some(pr) = probe {
            if let Some(ref server) = pr.http_server {
                if let Some(v) = extract_version(server, prefix) {
                    return Some(v);
                }
            }
        }
    }

    // Try extracting version from banner text.
    if let Some(b) = banner {
        // SSH banner special handling: "SSH-2.0-OpenSSH_8.9p1 ..."
        if b.starts_with("SSH-") {
            let version = b
                .strip_prefix("SSH-2.0-OpenSSH_")
                .or_else(|| b.strip_prefix("SSH-1.99-OpenSSH_"))
                .map(|rest| {
                    rest.split_whitespace()
                        .next()
                        .unwrap_or(rest)
                        .to_string()
                });
            if version.is_some() {
                return version;
            }
        }

        // SMTP/FTP banner: "220 ..." — extract the greeting text.
        if b.starts_with("220 ") || b.starts_with("220-") {
            return b.get(4..60).map(|s| s.trim().to_string());
        }

        // Redis version from INFO response.
        if b.starts_with("+PONG") || b.starts_with("$") {
            let bl = b.to_lowercase();
            if bl.contains("redis_version:") {
                return bl
                    .split("redis_version:")
                    .nth(1)
                    .and_then(|s| s.split_whitespace().next())
                    .map(|v| v.to_string());
            }
            return None;
        }

        // Memcached: "VERSION x.y.z"
        if b.starts_with("VERSION") {
            return b.strip_prefix("VERSION ").map(|v| v.trim().to_string());
        }

        // Elasticsearch JSON response.
        let bl = b.to_lowercase();
        if bl.contains("\"cluster_name\"")
            || bl.contains("\"tagline\":\"you know, for search\"")
        {
            return extract_json_field(b, "number");
        }

        // NATS INFO JSON.
        if b.starts_with("INFO {") || b.starts_with("INFO\t{") {
            return extract_json_field(b, "version");
        }

        // MySQL/MariaDB version.
        if bl.contains("mysql") || bl.contains("mariadb") {
            return extract_first_version(b);
        }

        // Generic version extraction from banner.
        if let Some(v) = extract_first_version(b) {
            return Some(v);
        }
    }

    None
}

// ─── Utility: count active connections to a port ────────────────────────────

/// Count active connections to a specific local port.
/// Uses the existing connection data passed in.
/// Excludes LISTEN-state entries so we only count actual client connections.
pub fn count_connections_to_port(port: u16, connections: &[crate::types::Connection]) -> u32 {
    connections
        .iter()
        .filter(|c| {
            c.local_port == port
                && c.state
                    .as_ref()
                    .map(|s| *s != crate::types::TcpState::Listen)
                    .unwrap_or(true)
        })
        .count() as u32
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Extract version string from a header value like "nginx/1.24.0" or "Apache/2.4.58".
fn extract_version(header: &str, prefix: &str) -> Option<String> {
    let lower_header = header.to_lowercase();
    let lower_prefix = prefix.to_lowercase();

    // Try "prefix/version" pattern
    if let Some(idx) = lower_header.find(&lower_prefix) {
        let after = &header[idx + prefix.len()..];
        if let Some(stripped) = after.strip_prefix('/') {
            let version = stripped
                .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
                .next()
                .unwrap_or(stripped);
            if !version.is_empty() {
                return Some(version.to_string());
            }
        }
    }
    None
}

/// Extract the first version-like string (digits and dots) from text.
fn extract_first_version(text: &str) -> Option<String> {
    let mut start = None;
    for (i, c) in text.char_indices() {
        if c.is_ascii_digit() || c == '.' || c == '-' {
            if start.is_none() && c.is_ascii_digit() {
                start = Some(i);
            }
        } else if start.is_some() {
            let s = &text[start.unwrap()..i];
            if s.contains('.') && s.len() >= 3 {
                return Some(s.trim_end_matches('.').to_string());
            }
            start = None;
        }
    }
    // Check tail
    if let Some(s) = start {
        let v = &text[s..];
        if v.contains('.') && v.len() >= 3 {
            return Some(v.trim_end_matches('.').to_string());
        }
    }
    None
}

/// Extract a string field from a JSON-like blob (simple, non-nested).
/// Looks for `"field":"value"` or `"field": "value"`.
fn extract_json_field(text: &str, field: &str) -> Option<String> {
    let pattern = format!("\"{}\"", field);
    if let Some(idx) = text.find(&pattern) {
        let after = &text[idx + pattern.len()..];
        // Skip optional whitespace and colon
        let after = after.trim_start().strip_prefix(':')?;
        let after = after.trim_start().strip_prefix('"')?;
        let end = after.find('"').unwrap_or(after.len());
        let value = &after[..end];
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper to call classify with minimal args ──

    fn classify_process(name: &str, exe: &str) -> (ServerKind, Option<String>) {
        classify(name, exe, "", 0, None)
    }

    fn classify_cmdline(cmdline: &str, process: &str) -> (ServerKind, Option<String>) {
        classify(process, "", cmdline, 0, None)
    }

    fn classify_port(port: u16) -> (ServerKind, Option<String>) {
        classify("", "", "", port, None)
    }

    #[test]
    fn test_port_only_never_matches() {
        // Port alone is never enough — any port can be used by any app.
        // All port-only classifications should return Unknown.
        assert!(matches!(classify_port(22).0, ServerKind::Unknown));
        assert!(matches!(classify_port(80).0, ServerKind::Unknown));
        assert!(matches!(classify_port(443).0, ServerKind::Unknown));
        assert!(matches!(classify_port(3306).0, ServerKind::Unknown));
        assert!(matches!(classify_port(5432).0, ServerKind::Unknown));
        assert!(matches!(classify_port(27017).0, ServerKind::Unknown));
    }

    #[test]
    fn test_process_plus_port_boosts_score() {
        // Process name + matching port should give a strong classification.
        let (kind, _) = classify("postgres.exe", "C:\\pgsql\\bin\\postgres.exe", "", 5432, None);
        assert_eq!(kind, ServerKind::PostgreSQL);

        let (kind, _) = classify("sshd.exe", "C:\\OpenSSH\\sshd.exe", "", 22, None);
        assert_eq!(kind, ServerKind::OpenSSH);

        let (kind, _) = classify("mysqld", "/usr/sbin/mysqld", "", 3306, None);
        assert_eq!(kind, ServerKind::MySQL);

        let (kind, _) = classify("redis-server", "/usr/bin/redis-server", "", 6379, None);
        assert_eq!(kind, ServerKind::Redis);
    }

    #[test]
    fn test_classify_by_process_node() {
        assert_eq!(
            classify_process("node.exe", "C:\\Program Files\\nodejs\\node.exe").0,
            ServerKind::NodeJs
        );
        assert_eq!(
            classify_process("node", "/usr/bin/node").0,
            ServerKind::NodeJs
        );
    }

    #[test]
    fn test_classify_by_process_databases() {
        assert_eq!(
            classify_process("postgres.exe", "C:\\pgsql\\bin\\postgres.exe").0,
            ServerKind::PostgreSQL
        );
        assert_eq!(
            classify_process("mysqld", "/usr/sbin/mysqld").0,
            ServerKind::MySQL
        );
        assert_eq!(
            classify_process("mongod.exe", "C:\\mongo\\bin\\mongod.exe").0,
            ServerKind::MongoDB
        );
        assert_eq!(
            classify_process("redis-server.exe", "C:\\redis\\redis-server.exe").0,
            ServerKind::Redis
        );
    }

    #[test]
    fn test_classify_by_cmdline_nextjs() {
        assert_eq!(
            classify_cmdline("node .next/standalone/server.js --port 3000", "node.exe").0,
            ServerKind::NextJs
        );
        assert_eq!(
            classify_cmdline("node next dev", "node").0,
            ServerKind::NextJs
        );
    }

    #[test]
    fn test_classify_by_cmdline_python_frameworks() {
        assert_eq!(
            classify_cmdline("python manage.py runserver 0.0.0.0:8000", "python.exe").0,
            ServerKind::Django
        );
        assert_eq!(
            classify_cmdline("python -m flask run", "python3").0,
            ServerKind::Flask
        );
        assert_eq!(
            classify_cmdline("python -m uvicorn main:app", "python").0,
            ServerKind::FastAPI
        );
    }

    #[test]
    fn test_classify_by_cmdline_java() {
        assert_eq!(
            classify_cmdline("java -jar spring-boot-app.jar", "java.exe").0,
            ServerKind::JavaSpringBoot
        );
        assert_eq!(
            classify_cmdline("java -cp catalina.jar org.apache.catalina.startup.Bootstrap", "java").0,
            ServerKind::JavaTomcat
        );
    }

    #[test]
    fn test_classify_by_cmdline_svchost() {
        // svchost + termservice -> RDP
        assert_eq!(
            classify_cmdline("svchost.exe -k TermService", "svchost.exe").0,
            ServerKind::RDP
        );
    }

    #[test]
    fn test_extract_version() {
        assert_eq!(
            extract_version("nginx/1.24.0", "nginx"),
            Some("1.24.0".to_string())
        );
        assert_eq!(
            extract_version("Apache/2.4.58 (Ubuntu)", "Apache"),
            Some("2.4.58".to_string())
        );
        assert_eq!(
            extract_version("Microsoft-IIS/10.0", "Microsoft-IIS"),
            Some("10.0".to_string())
        );
    }

    #[test]
    fn test_extract_json_field() {
        let json = r#"{"name":"test","version":"1.2.3","ok":true}"#;
        assert_eq!(extract_json_field(json, "version"), Some("1.2.3".to_string()));
        assert_eq!(extract_json_field(json, "name"), Some("test".to_string()));
        assert_eq!(extract_json_field(json, "missing"), None);
    }

    #[test]
    fn test_classify_by_banner_ssh() {
        let probe = ProbeResult {
            port: 22,
            banner: Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".to_string()),
            http_server: None,
            http_powered_by: None,
            http_title: None,
            http_headers: vec![],
            tls_detected: false,
            is_responsive: true,
        };
        let (kind, ver) = classify("sshd", "", "", 22, Some(&probe));
        assert!(matches!(kind, ServerKind::OpenSSH));
        assert_eq!(ver, Some("8.9p1".to_string()));
    }

    #[test]
    fn test_classify_by_banner_smtp() {
        let probe = ProbeResult {
            port: 25,
            banner: Some("220 mail.example.com ESMTP Postfix".to_string()),
            http_server: None,
            http_powered_by: None,
            http_title: None,
            http_headers: vec![],
            tls_detected: false,
            is_responsive: true,
        };
        let (kind, _ver) = classify("", "", "", 25, Some(&probe));
        assert!(matches!(kind, ServerKind::SMTP | ServerKind::Postfix));
    }

    #[test]
    fn test_classify_by_banner_redis() {
        let probe = ProbeResult {
            port: 6379,
            banner: Some("+PONG".to_string()),
            http_server: None,
            http_powered_by: None,
            http_title: None,
            http_headers: vec![],
            tls_detected: false,
            is_responsive: true,
        };
        let (kind, _ver) = classify("redis-server", "", "", 6379, Some(&probe));
        assert!(matches!(kind, ServerKind::Redis));
    }

    #[test]
    fn test_classify_by_process_path_fallback() {
        // Unknown process name but recognizable path
        assert_eq!(
            classify_process("server", "C:\\Program Files\\PostgreSQL\\15\\bin\\server.exe").0,
            ServerKind::PostgreSQL
        );
        assert_eq!(
            classify_process("custom", "/opt/kafka/bin/custom").0,
            ServerKind::Kafka
        );
    }

    #[test]
    fn test_classify_by_cmdline_vite() {
        assert_eq!(
            classify_cmdline("node ./node_modules/.bin/vite --port 5173", "node.exe").0,
            ServerKind::ViteDevServer
        );
    }

    #[test]
    fn test_extract_first_version() {
        // "5.7.38-log": version extraction stops at 'l', yielding "5.7.38-"
        assert_eq!(extract_first_version("5.7.38-log"), Some("5.7.38-".to_string()));
        assert_eq!(extract_first_version("something 10.6.12-MariaDB"), Some("10.6.12-".to_string()));
        assert_eq!(extract_first_version("noversion"), None);
    }
}
