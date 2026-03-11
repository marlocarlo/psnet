//! Wappalyzer-style HTTP header fingerprint database.
//!
//! Signatures are loaded from `data/wappalyzer.json` (embedded at compile time).
//! To add new signatures or sync with upstream Wappalyzer data, edit the JSON file.
//!
//! Sync with upstream:
//!   1. Clone https://github.com/dochne/wappalyzer
//!   2. Run: scripts/sync_wappalyzer.py (converts their format to ours)
//!   3. Rebuild psnet

use std::sync::OnceLock;
use super::types::DetectedTech;

// ─── Signature struct ───────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct HeaderSig {
    name: String,
    category: String,
    header: String,
    pattern: String,
    version_prefix: String,
}

// ─── Embedded JSON database ─────────────────────────────────────────────────

static WAPPALYZER_JSON: &str = include_str!("../../../data/wappalyzer.json");

static SIGNATURES: OnceLock<Vec<HeaderSig>> = OnceLock::new();

fn signatures() -> &'static [HeaderSig] {
    SIGNATURES.get_or_init(|| load_signatures(WAPPALYZER_JSON))
}

fn load_signatures(json: &str) -> Vec<HeaderSig> {
    let entries: Vec<serde_json::Value> = serde_json::from_str(json)
        .expect("wappalyzer.json: invalid JSON");

    entries
        .into_iter()
        .filter_map(|v| {
            Some(HeaderSig {
                name: v.get("name")?.as_str()?.to_string(),
                category: v.get("category")?.as_str()?.to_string(),
                header: v.get("header")?.as_str()?.to_string(),
                pattern: v.get("pattern").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                version_prefix: v.get("version_prefix").and_then(|s| s.as_str()).unwrap_or("").to_string(),
            })
        })
        .collect()
}

// ─── Detection engine ───────────────────────────────────────────────────────

/// Detect technologies from HTTP headers using the Wappalyzer signature database.
/// Returns all matching technologies (there can be multiple: e.g., Nginx + PHP + WordPress).
pub fn detect_from_headers(
    headers: &[(String, String)],
    server_header: Option<&str>,
    powered_by: Option<&str>,
) -> Vec<DetectedTech> {
    let sigs = signatures();
    let mut results: Vec<DetectedTech> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Build lowercase header map for efficient lookup
    let header_map: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.to_lowercase()))
        .collect();

    let server_lower = server_header.map(|s| s.to_lowercase());
    let powered_lower = powered_by.map(|s| s.to_lowercase());

    for sig in sigs {
        let matched = match sig.header.as_str() {
            "server" => {
                if let Some(ref sv) = server_lower {
                    if sig.pattern.is_empty() { true } else { sv.contains(sig.pattern.as_str()) }
                } else {
                    check_header_map(&header_map, &sig.header, &sig.pattern)
                }
            }
            "x-powered-by" => {
                if let Some(ref pb) = powered_lower {
                    if sig.pattern.is_empty() { true } else { pb.contains(sig.pattern.as_str()) }
                } else {
                    check_header_map(&header_map, &sig.header, &sig.pattern)
                }
            }
            _ => check_header_map(&header_map, &sig.header, &sig.pattern),
        };

        if !matched { continue; }

        if !seen.insert(sig.name.as_str() as *const str) { continue; }

        let version = if !sig.version_prefix.is_empty() {
            let source = match sig.header.as_str() {
                "server" => server_header.unwrap_or(""),
                "x-powered-by" => powered_by.unwrap_or(""),
                _ => headers
                    .iter()
                    .find(|(k, _)| k.to_lowercase() == sig.header)
                    .map(|(_, v)| v.as_str())
                    .unwrap_or(""),
            };
            extract_header_version(source, &sig.version_prefix)
        } else {
            String::new()
        };

        results.push(DetectedTech {
            name: sig.name.clone(),
            category: sig.category.clone(),
            version,
        });
    }

    results
}

fn check_header_map(headers: &[(String, String)], header_name: &str, pattern: &str) -> bool {
    for (k, v) in headers {
        if k == header_name {
            if pattern.is_empty() { return true; }
            if v.contains(pattern) { return true; }
        }
    }
    false
}

fn extract_header_version(header_value: &str, prefix: &str) -> String {
    let lower = header_value.to_lowercase();
    let prefix_lower = prefix.to_lowercase();

    if let Some(idx) = lower.find(&prefix_lower) {
        let after = &header_value[idx + prefix.len()..];
        if let Some(rest) = after.strip_prefix('/') {
            let version: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
                .collect();
            if !version.is_empty() {
                return version;
            }
        }
    }
    String::new()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_nginx() {
        let techs = detect_from_headers(&[], Some("nginx/1.24.0"), None);
        assert!(techs.iter().any(|t| t.name == "Nginx"));
        let nginx = techs.iter().find(|t| t.name == "Nginx").unwrap();
        assert_eq!(nginx.version, "1.24.0");
    }

    #[test]
    fn test_detect_php_powered_by() {
        let techs = detect_from_headers(&[], None, Some("PHP/8.2.0"));
        assert!(techs.iter().any(|t| t.name == "PHP"));
    }

    #[test]
    fn test_detect_multiple_technologies() {
        let techs = detect_from_headers(
            &[("x-powered-by".to_string(), "Express".to_string())],
            Some("nginx/1.24.0"),
            None,
        );
        assert!(techs.iter().any(|t| t.name == "Nginx"));
        assert!(techs.iter().any(|t| t.name == "Express"));
    }
}
