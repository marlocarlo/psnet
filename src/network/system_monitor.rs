//! System-level security monitoring — GlassWire-style change detection.
//!
//! Monitors: hosts file tampering, proxy setting changes, WiFi evil twin
//! attacks, and application binary integrity. All checks are fault-tolerant
//! and will silently return empty results on errors rather than crashing.

use std::collections::HashMap;
use std::fs;
use std::net::TcpStream;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ─── System event type ──────────────────────────────────────────────────────

/// Security-relevant system change detected by the monitor.
#[derive(Clone, Debug)]
pub enum SystemEvent {
    /// The hosts file content was modified.
    HostsFileChanged(String),
    /// Windows proxy settings were changed.
    ProxyChanged(String),
    /// A known SSID appeared with an unexpected BSSID (evil twin indicator).
    EvilTwinDetected(String),
    /// A tracked application's binary hash changed on disk.
    AppBinaryChanged { app: String, detail: String },
    /// Internet connectivity was lost.
    InternetLost(String),
    /// Internet connectivity was restored.
    InternetRestored,
}

// ─── Proxy state snapshot ───────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProxyState {
    enabled: bool,
    server: String,
    auto_config_url: String,
}

impl Default for ProxyState {
    fn default() -> Self {
        Self {
            enabled: false,
            server: String::new(),
            auto_config_url: String::new(),
        }
    }
}

// ─── WiFi network record ────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct WifiNetwork {
    ssid: String,
    bssid: String,
    encryption: String,
}

// ─── Tracked app record ─────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct TrackedApp {
    exe_path: String,
    hash: u64,
}

// ─── FNV-1a hash (fast, no dependencies) ────────────────────────────────────

fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;

    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

// ─── SystemMonitor ──────────────────────────────────────────────────────────

/// Monitors system-level security indicators.
///
/// Tracks hosts file changes, proxy setting mutations, WiFi evil twin
/// attacks, and application binary integrity. Each category runs on its
/// own tick interval to avoid excessive I/O on every frame.
pub struct SystemMonitor {
    /// FNV hash of the last-read hosts file content.
    hosts_hash: Option<u64>,
    /// Last known proxy configuration.
    proxy_state: Option<ProxyState>,
    /// Known SSID → set of observed BSSIDs.
    known_wifi: HashMap<String, Vec<String>>,
    /// Tracked application binaries: process_name → TrackedApp.
    tracked_apps: HashMap<String, TrackedApp>,
    /// Monotonic tick counter.
    tick_count: u64,
    /// Cached internet availability (None = not yet checked)
    internet_available: Option<bool>,
    /// Result from background connectivity check thread
    connectivity_result: Arc<Mutex<Option<bool>>>,
    /// Whether a connectivity check is in progress
    connectivity_checking: Arc<Mutex<bool>>,
}

impl SystemMonitor {
    pub fn new() -> Self {
        Self {
            hosts_hash: None,
            proxy_state: None,
            known_wifi: HashMap::new(),
            tracked_apps: HashMap::new(),
            tick_count: 0,
            internet_available: None,
            connectivity_result: Arc::new(Mutex::new(None)),
            connectivity_checking: Arc::new(Mutex::new(false)),
        }
    }

    // ── Master tick ─────────────────────────────────────────────────────

    /// Run all periodic checks and return any detected events.
    ///
    /// Check intervals (to avoid excessive I/O):
    /// - Hosts file / proxy: every 30 ticks
    /// - WiFi security: every 60 ticks
    /// - App binary hashes: every 120 ticks
    pub fn tick(&mut self) -> Vec<SystemEvent> {
        let mut events = Vec::new();
        let tick = self.tick_count;
        self.tick_count = self.tick_count.wrapping_add(1);

        // Hosts file + proxy — every 30 ticks
        if tick % 30 == 0 {
            if let Some(desc) = self.check_hosts_file() {
                events.push(SystemEvent::HostsFileChanged(desc));
            }
            if let Some(desc) = self.check_proxy_settings() {
                events.push(SystemEvent::ProxyChanged(desc));
            }
        }

        // WiFi evil twin — every 60 ticks
        if tick % 60 == 0 {
            for warning in self.check_wifi_security() {
                events.push(SystemEvent::EvilTwinDetected(warning));
            }
        }

        // App binary integrity — every 120 ticks
        if tick % 120 == 0 {
            for (app, detail) in self.check_app_changes() {
                events.push(SystemEvent::AppBinaryChanged { app, detail });
            }
        }

        // Internet connectivity — every 60 ticks
        if tick % 60 == 0 {
            self.start_connectivity_check();
        }
        if let Some(event) = self.poll_connectivity() {
            events.push(event);
        }

        events
    }

    // ── 1. Hosts file monitoring ────────────────────────────────────────

    /// Read the hosts file and compare its hash to the previously stored
    /// value. Returns a description string if the file changed, or `None`
    /// on first run / no change / read error.
    pub fn check_hosts_file(&mut self) -> Option<String> {
        let path = r"C:\Windows\System32\drivers\etc\hosts";
        let content = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => return None, // Can't read — skip silently
        };

        let hash = fnv1a_hash(&content);

        match self.hosts_hash {
            None => {
                // First read — establish baseline, no alert.
                self.hosts_hash = Some(hash);
                None
            }
            Some(prev) if prev == hash => None,
            Some(_) => {
                self.hosts_hash = Some(hash);
                let line_count = content.iter().filter(|&&b| b == b'\n').count();
                Some(format!(
                    "Hosts file modified ({} lines, hash {:016x})",
                    line_count, hash
                ))
            }
        }
    }

    // ── 2. Proxy settings monitoring ────────────────────────────────────

    /// Query Windows proxy settings from the registry and compare to the
    /// previously stored state. Returns a description if anything changed.
    pub fn check_proxy_settings(&mut self) -> Option<String> {
        let current = read_proxy_state();

        match &self.proxy_state {
            None => {
                // First read — establish baseline, no alert.
                self.proxy_state = Some(current);
                None
            }
            Some(prev) if *prev == current => None,
            Some(prev) => {
                let mut changes = Vec::new();

                if prev.enabled != current.enabled {
                    changes.push(format!(
                        "proxy {}",
                        if current.enabled { "enabled" } else { "disabled" }
                    ));
                }
                if prev.server != current.server {
                    if current.server.is_empty() {
                        changes.push("proxy server cleared".to_string());
                    } else {
                        changes.push(format!("proxy server → {}", current.server));
                    }
                }
                if prev.auto_config_url != current.auto_config_url {
                    if current.auto_config_url.is_empty() {
                        changes.push("auto-config URL cleared".to_string());
                    } else {
                        changes.push(format!(
                            "auto-config URL → {}",
                            current.auto_config_url
                        ));
                    }
                }

                self.proxy_state = Some(current);

                if changes.is_empty() {
                    None
                } else {
                    Some(format!("Proxy settings changed: {}", changes.join(", ")))
                }
            }
        }
    }

    // ── 3. WiFi / evil twin detection ───────────────────────────────────

    /// Scan visible WiFi networks via `netsh wlan show networks` and check
    /// for evil twin indicators:
    /// - A previously-seen SSID appearing with a new/different BSSID
    /// - A connected network losing its encryption
    ///
    /// Returns a list of warning strings (empty if nothing suspicious).
    pub fn check_wifi_security(&mut self) -> Vec<String> {
        let networks = scan_wifi_networks();
        if networks.is_empty() {
            return Vec::new();
        }

        let mut warnings = Vec::new();

        for net in &networks {
            if net.ssid.is_empty() {
                continue;
            }

            let known_bssids = self
                .known_wifi
                .entry(net.ssid.clone())
                .or_insert_with(Vec::new);

            if known_bssids.is_empty() {
                // First sighting — learn it.
                known_bssids.push(net.bssid.clone());
            } else if !known_bssids.contains(&net.bssid) {
                // New BSSID for a known SSID — possible evil twin.
                warnings.push(format!(
                    "SSID \"{}\" seen with new BSSID {} (known: {})",
                    net.ssid,
                    net.bssid,
                    known_bssids.join(", ")
                ));
                known_bssids.push(net.bssid.clone());
            }

            // Warn if encryption is missing on a non-open network.
            let enc_lower = net.encryption.to_lowercase();
            if enc_lower.contains("open") || enc_lower.contains("none") {
                warnings.push(format!(
                    "SSID \"{}\" (BSSID {}) has no encryption",
                    net.ssid, net.bssid
                ));
            }
        }

        warnings
    }

    // ── 4. App binary hash tracking ─────────────────────────────────────

    /// Register an application for binary integrity monitoring.
    /// The executable at `exe_path` is hashed immediately and stored
    /// under `process_name`. If the file cannot be read, the app is
    /// silently not tracked.
    pub fn track_app(&mut self, process_name: &str, exe_path: &str) {
        if let Ok(bytes) = fs::read(exe_path) {
            let hash = fnv1a_hash(&bytes);
            self.tracked_apps.insert(
                process_name.to_string(),
                TrackedApp {
                    exe_path: exe_path.to_string(),
                    hash,
                },
            );
        }
    }

    /// Re-hash every tracked application binary and return a list of
    /// `(process_name, description)` for any that changed since last check.
    pub fn check_app_changes(&mut self) -> Vec<(String, String)> {
        let mut changed = Vec::new();

        for (name, tracked) in &mut self.tracked_apps {
            match fs::read(&tracked.exe_path) {
                Ok(bytes) => {
                    let new_hash = fnv1a_hash(&bytes);
                    if new_hash != tracked.hash {
                        changed.push((
                            name.clone(),
                            format!(
                                "Binary changed: {} (hash {:016x} → {:016x})",
                                tracked.exe_path, tracked.hash, new_hash
                            ),
                        ));
                        tracked.hash = new_hash;
                    }
                }
                Err(_) => {
                    // File disappeared or became unreadable.
                    changed.push((
                        name.clone(),
                        format!("Binary no longer readable: {}", tracked.exe_path),
                    ));
                }
            }
        }

        changed
    }

    /// Spawn a background connectivity check (non-blocking).
    fn start_connectivity_check(&self) {
        if let Ok(mut checking) = self.connectivity_checking.lock() {
            if *checking { return; }
            *checking = true;
        } else {
            return;
        }
        let result = Arc::clone(&self.connectivity_result);
        let checking = Arc::clone(&self.connectivity_checking);
        thread::spawn(move || {
            let available = TcpStream::connect_timeout(
                &"8.8.8.8:53".parse().unwrap(),
                Duration::from_secs(3),
            ).is_ok();
            if let Ok(mut r) = result.lock() {
                *r = Some(available);
            }
            if let Ok(mut c) = checking.lock() {
                *c = false;
            }
        });
    }

    /// Poll the background connectivity result and emit a SystemEvent if state changed.
    pub fn poll_connectivity(&mut self) -> Option<SystemEvent> {
        let result = if let Ok(mut r) = self.connectivity_result.lock() {
            r.take()
        } else {
            None
        };
        let available = result?;
        match self.internet_available {
            None => {
                self.internet_available = Some(available);
                None
            }
            Some(prev) if prev == available => None,
            Some(false) => {
                self.internet_available = Some(true);
                Some(SystemEvent::InternetRestored)
            }
            Some(true) => {
                self.internet_available = Some(false);
                Some(SystemEvent::InternetLost("Cannot reach 8.8.8.8:53".to_string()))
            }
        }
    }

    /// Number of applications currently tracked for binary integrity.
    pub fn tracked_app_count(&self) -> usize {
        self.tracked_apps.len()
    }

    /// Number of known WiFi SSIDs being monitored.
    pub fn known_wifi_count(&self) -> usize {
        self.known_wifi.len()
    }
}

// ─── Registry / system helpers ──────────────────────────────────────────────

/// Read proxy settings from the Windows registry via `reg query`.
fn read_proxy_state() -> ProxyState {
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    let output = match Command::new("reg")
        .args(["query", key, "/v", "ProxyEnable"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return ProxyState::default(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    let enabled = parse_reg_dword(&text).unwrap_or(0) != 0;

    let server = query_reg_string(key, "ProxyServer");
    let auto_config = query_reg_string(key, "AutoConfigURL");

    ProxyState {
        enabled,
        server,
        auto_config_url: auto_config,
    }
}

/// Query a REG_SZ value from the registry.
fn query_reg_string(key: &str, value_name: &str) -> String {
    let output = match Command::new("reg")
        .args(["query", key, "/v", value_name])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return String::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    parse_reg_sz(&text).unwrap_or_default()
}

/// Parse a REG_DWORD value from `reg query` output.
/// Expected line format: `    ProxyEnable    REG_DWORD    0x0`
fn parse_reg_dword(output: &str) -> Option<u32> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("REG_DWORD") {
            // Last whitespace-delimited token is the value.
            if let Some(val_str) = trimmed.split_whitespace().last() {
                let val_str = val_str.trim_start_matches("0x");
                return u32::from_str_radix(val_str, 16).ok();
            }
        }
    }
    None
}

/// Parse a REG_SZ value from `reg query` output.
/// Expected line format: `    ProxyServer    REG_SZ    http://proxy:8080`
fn parse_reg_sz(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.contains("REG_SZ") {
            let parts: Vec<&str> = trimmed.splitn(3, "REG_SZ").collect();
            if parts.len() >= 2 {
                return Some(parts[1].trim().to_string());
            }
        }
    }
    None
}

// ─── WiFi scanning ──────────────────────────────────────────────────────────

/// Run `netsh wlan show networks mode=bssid` and parse the output into
/// a list of visible networks with their SSIDs, BSSIDs, and encryption type.
fn scan_wifi_networks() -> Vec<WifiNetwork> {
    let output = match Command::new("netsh")
        .args(["wlan", "show", "networks", "mode=bssid"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let text = String::from_utf8_lossy(&output.stdout);
    parse_wifi_output(&text)
}

/// Parse the multi-block output from `netsh wlan show networks mode=bssid`.
///
/// The output looks like:
/// ```text
/// SSID 1 : MyNetwork
///     Network type            : Infrastructure
///     Authentication          : WPA2-Personal
///     Encryption              : CCMP
///     BSSID 1                 : aa:bb:cc:dd:ee:ff
///         Signal              : 85%
///         ...
///     BSSID 2                 : 11:22:33:44:55:66
///         Signal              : 42%
///         ...
/// ```
///
/// Each SSID block can contain multiple BSSIDs. We emit one `WifiNetwork`
/// entry per BSSID.
fn parse_wifi_output(text: &str) -> Vec<WifiNetwork> {
    let mut networks = Vec::new();
    let mut current_ssid = String::new();
    let mut current_encryption = String::new();

    for line in text.lines() {
        let trimmed = line.trim();

        if let Some(rest) = strip_field_prefix(trimmed, "SSID") {
            // Filter out BSSID lines — those start with "BSSID".
            if !trimmed.starts_with("BSSID") {
                current_ssid = rest.to_string();
            }
        }

        if let Some(rest) = strip_field_prefix(trimmed, "Encryption") {
            current_encryption = rest.to_string();
        }

        if let Some(rest) = strip_field_prefix(trimmed, "BSSID") {
            if !current_ssid.is_empty() {
                networks.push(WifiNetwork {
                    ssid: current_ssid.clone(),
                    bssid: rest.to_string(),
                    encryption: current_encryption.clone(),
                });
            }
        }
    }

    networks
}

/// Strip a field prefix like `"SSID 1 :"` or `"Encryption :"` and return
/// the value portion. Handles the `netsh` output format where the field
/// name is followed by an optional index number and a colon.
fn strip_field_prefix<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    if !line.starts_with(field) {
        return None;
    }
    // Find the colon separator.
    if let Some(colon_pos) = line.find(':') {
        let value = line[colon_pos + 1..].trim();
        Some(value)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_produces_consistent_hash() {
        let data = b"hello world";
        let h1 = fnv1a_hash(data);
        let h2 = fnv1a_hash(data);
        assert_eq!(h1, h2);
        assert_ne!(h1, 0);
    }

    #[test]
    fn fnv1a_different_data_different_hash() {
        let h1 = fnv1a_hash(b"hello");
        let h2 = fnv1a_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn parse_reg_dword_hex() {
        let output = "    ProxyEnable    REG_DWORD    0x1\r\n";
        assert_eq!(parse_reg_dword(output), Some(1));
    }

    #[test]
    fn parse_reg_dword_zero() {
        let output = "    ProxyEnable    REG_DWORD    0x0\r\n";
        assert_eq!(parse_reg_dword(output), Some(0));
    }

    #[test]
    fn parse_reg_dword_missing() {
        let output = "ERROR: The system was unable to find the specified registry key.\r\n";
        assert_eq!(parse_reg_dword(output), None);
    }

    #[test]
    fn parse_reg_sz_value() {
        let output = "    ProxyServer    REG_SZ    http://proxy:8080\r\n";
        assert_eq!(
            parse_reg_sz(output),
            Some("http://proxy:8080".to_string())
        );
    }

    #[test]
    fn parse_reg_sz_empty() {
        let output = "    AutoConfigURL    REG_SZ    \r\n";
        assert_eq!(parse_reg_sz(output), Some(String::new()));
    }

    #[test]
    fn parse_wifi_output_multiple_bssids() {
        let text = "\
SSID 1 : HomeNetwork
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
        Signal              : 85%
        Radio type          : 802.11ac
        Channel             : 36
    BSSID 2                 : 11:22:33:44:55:66
        Signal              : 42%
        Radio type          : 802.11n
        Channel             : 6

SSID 2 : CoffeeShop
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : de:ad:be:ef:00:01
        Signal              : 60%
";
        let nets = parse_wifi_output(text);
        assert_eq!(nets.len(), 3);

        assert_eq!(nets[0].ssid, "HomeNetwork");
        assert_eq!(nets[0].bssid, "aa:bb:cc:dd:ee:ff");
        assert_eq!(nets[0].encryption, "CCMP");

        assert_eq!(nets[1].ssid, "HomeNetwork");
        assert_eq!(nets[1].bssid, "11:22:33:44:55:66");

        assert_eq!(nets[2].ssid, "CoffeeShop");
        assert_eq!(nets[2].bssid, "de:ad:be:ef:00:01");
        assert_eq!(nets[2].encryption, "None");
    }

    #[test]
    fn parse_wifi_empty_output() {
        assert!(parse_wifi_output("").is_empty());
        assert!(parse_wifi_output("No wireless interfaces found.\n").is_empty());
    }

    #[test]
    fn strip_field_prefix_basic() {
        assert_eq!(
            strip_field_prefix("SSID 1 : MyNet", "SSID"),
            Some("MyNet")
        );
        assert_eq!(
            strip_field_prefix("Encryption              : CCMP", "Encryption"),
            Some("CCMP")
        );
        assert_eq!(strip_field_prefix("Signal : 85%", "SSID"), None);
    }

    #[test]
    fn system_monitor_new_is_clean() {
        let mon = SystemMonitor::new();
        assert_eq!(mon.tracked_app_count(), 0);
        assert_eq!(mon.known_wifi_count(), 0);
    }

    #[test]
    fn evil_twin_detection_logic() {
        let mut mon = SystemMonitor::new();

        // Simulate learning a network.
        mon.known_wifi
            .insert("TestNet".to_string(), vec!["aa:bb:cc:dd:ee:ff".to_string()]);

        // Simulate a second scan with same SSID but different BSSID.
        mon.known_wifi
            .entry("TestNet".to_string())
            .and_modify(|bssids| {
                if !bssids.contains(&"11:22:33:44:55:66".to_string()) {
                    bssids.push("11:22:33:44:55:66".to_string());
                }
            });

        let bssids = mon.known_wifi.get("TestNet").unwrap();
        assert_eq!(bssids.len(), 2);
    }

    #[test]
    fn proxy_state_equality() {
        let a = ProxyState {
            enabled: true,
            server: "proxy:8080".to_string(),
            auto_config_url: String::new(),
        };
        let b = ProxyState {
            enabled: true,
            server: "proxy:8080".to_string(),
            auto_config_url: String::new(),
        };
        let c = ProxyState {
            enabled: false,
            server: "proxy:8080".to_string(),
            auto_config_url: String::new(),
        };
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
