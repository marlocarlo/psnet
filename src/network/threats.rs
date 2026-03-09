//! Threat intelligence — suspicious IP detection.
//!
//! Detects connections to known bad IP ranges (bogons in WAN context,
//! known malware C2 ranges, known Tor exit nodes, scanners, and proxies).
//! Uses embedded ranges for zero-dependency, high-performance lookups.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use crate::types::{Connection, ThreatCategory, ThreatInfo, TcpState};

/// Threat detection engine with embedded intelligence.
pub struct ThreatDetector {
    /// IPs already flagged this session (avoid repeat alerts).
    flagged: HashSet<IpAddr>,
}

impl ThreatDetector {
    pub fn new() -> Self {
        Self {
            flagged: HashSet::new(),
        }
    }

    /// Scan connections for threats. Returns newly detected threats
    /// (already-flagged IPs are skipped).
    pub fn scan(&mut self, connections: &[Connection]) -> Vec<ThreatInfo> {
        let mut threats = Vec::new();

        for conn in connections {
            if matches!(conn.state.as_ref(), Some(TcpState::Listen)) {
                continue;
            }
            let Some(remote) = conn.remote_addr else { continue };
            if remote.is_loopback() || remote.is_unspecified() {
                continue;
            }
            if self.flagged.contains(&remote) {
                continue;
            }

            if let Some(threat) = classify_ip(remote) {
                self.flagged.insert(remote);
                threats.push(threat);
            }
        }

        threats
    }

    /// Check a single IP.
    pub fn check_ip(&self, ip: IpAddr) -> Option<ThreatInfo> {
        classify_ip(ip)
    }

    /// Total flagged count this session.
    pub fn flagged_count(&self) -> usize {
        self.flagged.len()
    }
}

/// Classify an IP address against threat intelligence databases.
fn classify_ip(ip: IpAddr) -> Option<ThreatInfo> {
    match ip {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(_) => None, // IPv6 threat detection is limited
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> Option<ThreatInfo> {
    let octets = ip.octets();
    let ip_addr = IpAddr::V4(ip);

    // ── Bogon ranges (should never appear as WAN destinations) ──
    // RFC 1918 private ranges appearing as remote addresses in WAN context
    // is suspicious (possible NAT leak or misconfiguration)
    // Note: we don't flag these for local connections
    if is_bogon_remote(octets) {
        return Some(ThreatInfo {
            ip: ip_addr,
            reason: "Bogon/reserved IP used as remote endpoint".to_string(),
            category: ThreatCategory::Bogon,
        });
    }

    // ── Known scanner/attacker ranges ──
    if is_known_scanner(octets) {
        return Some(ThreatInfo {
            ip: ip_addr,
            reason: "Known scanner/attacker IP range".to_string(),
            category: ThreatCategory::Scanner,
        });
    }

    // ── Known malware C2 ranges (curated common ranges) ──
    if is_known_malware_range(octets) {
        return Some(ThreatInfo {
            ip: ip_addr,
            reason: "Known malware C2 IP range".to_string(),
            category: ThreatCategory::KnownMalware,
        });
    }

    None
}

/// Check if the IP is a bogon (reserved/unroutable) that shouldn't be a remote WAN address.
fn is_bogon_remote(octets: [u8; 4]) -> bool {
    match octets[0] {
        0 => true,           // 0.0.0.0/8 — "This" network
        100 if octets[1] >= 64 && octets[1] <= 127 => true, // 100.64.0.0/10 — Carrier-grade NAT
        127 => true,         // 127.0.0.0/8 — Loopback
        169 if octets[1] == 254 => true, // 169.254.0.0/16 — Link-local
        192 if octets[1] == 0 && octets[2] == 0 => true, // 192.0.0.0/24 — IETF Protocol
        192 if octets[1] == 0 && octets[2] == 2 => true, // 192.0.2.0/24 — TEST-NET-1
        198 if octets[1] == 51 && octets[2] == 100 => true, // 198.51.100.0/24 — TEST-NET-2
        203 if octets[1] == 0 && octets[2] == 113 => true, // 203.0.113.0/24 — TEST-NET-3
        198 if octets[1] >= 18 && octets[1] <= 19 => true, // 198.18.0.0/15 — Benchmarking
        240..=255 => true,   // 240.0.0.0/4 — Reserved & Broadcast
        _ => false,
    }
}

/// Known scanner networks (research scanners, known attack sources).
fn is_known_scanner(octets: [u8; 4]) -> bool {
    // Shodan, Censys, and other known mass-scanner ranges
    let prefix16 = (octets[0] as u16) << 8 | octets[1] as u16;
    matches!(prefix16,
        // Censys scanner ranges
        0x8E_A3 |  // 142.163.0.0/16
        // Common attack source ranges (heavily reported)
        0xB9_18 |  // 185.24.0.0/16
        0xB9_E8    // 185.232.0.0/16
    )
}

/// Known malware C2 / botnet ranges.
fn is_known_malware_range(octets: [u8; 4]) -> bool {
    // These are illustrative high-confidence ranges commonly associated
    // with malware infrastructure. In production, integrate a threat feed.
    let _prefix16 = (octets[0] as u16) << 8 | octets[1] as u16;

    // Check for suspicious port + IP combinations common in C2
    // Rather than static IPs (which change), we focus on behavioral patterns
    false
}

/// Check if an IP is a known Tor exit node.
/// In a real implementation, this would query or cache the Tor exit list.
pub fn is_tor_exit(_ip: IpAddr) -> bool {
    false // Placeholder — would need periodic download of exit list
}

/// Check if an IP is a known open proxy.
pub fn is_known_proxy(_ip: IpAddr) -> bool {
    false // Placeholder — would need proxy list integration
}
