//! WSL (Windows Subsystem for Linux) instance discovery.
//!
//! Uses multiple methods to accurately identify all WSL hosts:
//!   1. `wsl --list --verbose` — distro name, state, and WSL version (1 or 2)
//!   2. `wsl -d <distro> -- hostname -I` — primary IP address
//!   3. `wsl -d <distro> -- cat /etc/os-release` — distro description & version
//!   4. `wsl -d <distro> -- ip addr show eth0` — all IPs + MAC address
//!   5. `wsl -d <distro> -- uname -r` — kernel version
//!   6. `wsl -d <distro> -- cat /etc/hostname` — actual Linux hostname
//!
//! Silently returns empty if WSL is not installed.

use std::net::Ipv4Addr;
use std::process::Command;

/// A discovered WSL instance with rich metadata.
#[derive(Clone, Debug)]
pub struct WslInstance {
    /// Distro name as registered in WSL (e.g., "Ubuntu", "Debian").
    pub name: String,
    /// Whether this instance is currently running.
    pub is_running: bool,
    /// WSL version: 1 or 2 (0 if unknown).
    pub wsl_version: u8,
    /// Primary IPv4 address (from hostname -I or ip addr).
    pub ip: Option<Ipv4Addr>,
    /// All IPv4 addresses found on this instance.
    pub all_ips: Vec<Ipv4Addr>,
    /// MAC address of eth0 (WSL2 only, empty for WSL1).
    pub mac: String,
    /// Whether this is the default WSL distro.
    pub is_default: bool,
    /// Linux hostname inside the distro.
    pub linux_hostname: String,
    /// OS pretty name from /etc/os-release (e.g., "Ubuntu 22.04.3 LTS").
    pub os_pretty_name: String,
    /// OS ID from /etc/os-release (e.g., "ubuntu", "debian", "alpine").
    pub os_id: String,
    /// OS version from /etc/os-release.
    pub os_version: String,
    /// Kernel version from uname -r.
    pub kernel: String,
}

/// Discover all WSL instances (running and stopped) with full metadata.
pub fn discover() -> Vec<WslInstance> {
    // Method 1: `wsl --list --verbose` for names, states, and versions
    let mut instances = discover_verbose();
    if instances.is_empty() {
        // Fallback: try --list --running --quiet (older WSL versions)
        instances = discover_running_only();
    }

    // For each running instance, gather detailed info in parallel-ish fashion
    for inst in &mut instances {
        if !inst.is_running {
            continue;
        }

        // Method 2 & 4: Get IPs — try ip addr first (more complete), fallback to hostname -I
        let (ips, mac) = get_network_info(&inst.name);
        if !ips.is_empty() {
            inst.all_ips = ips;
            inst.ip = inst.all_ips.first().copied();
            inst.mac = mac;
        } else {
            // Fallback: hostname -I
            inst.ip = get_wsl_ip_hostname(&inst.name);
            if let Some(ip) = inst.ip {
                inst.all_ips = vec![ip];
            }
        }

        // Method 3: OS release info
        let (pretty_name, os_id, os_version) = get_os_release(&inst.name);
        inst.os_pretty_name = pretty_name;
        inst.os_id = os_id;
        inst.os_version = os_version;

        // Method 5: Kernel version
        inst.kernel = get_kernel(&inst.name);

        // Method 6: Linux hostname
        inst.linux_hostname = get_linux_hostname(&inst.name);
    }

    instances
}

// ─── Method 1: wsl --list --verbose ─────────────────────────────────────────

/// Parse `wsl --list --verbose` to get distro name, state, and WSL version.
/// Output format:
/// ```
///   NAME            STATE           VERSION
/// * Ubuntu          Running         2
///   Debian          Stopped         2
///   Alpine          Running         1
/// ```
fn discover_verbose() -> Vec<WslInstance> {
    let output = Command::new("wsl")
        .args(["--list", "--verbose"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = decode_wsl_output(&output.stdout);
    let mut instances = Vec::new();

    for line in stdout.lines().skip(1) {
        // Skip header line
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let is_default = line.starts_with('*');
        let line = line.trim_start_matches('*').trim();

        // Split into columns — name, state, version
        // The columns are space-separated but name can't contain spaces in WSL
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let name = parts[0].to_string();

        // State is usually "Running" or "Stopped"
        let state_str = parts.get(1).unwrap_or(&"");
        let is_running = state_str.eq_ignore_ascii_case("running");

        // Version is the last column (1 or 2)
        let wsl_version = parts.last()
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(0);

        instances.push(WslInstance {
            name,
            is_running,
            wsl_version,
            ip: None,
            all_ips: Vec::new(),
            mac: String::new(),
            is_default,
            linux_hostname: String::new(),
            os_pretty_name: String::new(),
            os_id: String::new(),
            os_version: String::new(),
            kernel: String::new(),
        });
    }

    instances
}

/// Fallback: `wsl --list --running --quiet` (no version info).
fn discover_running_only() -> Vec<WslInstance> {
    let output = Command::new("wsl")
        .args(["--list", "--running", "--quiet"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = decode_wsl_output(&output.stdout);
    stdout.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .map(|name| WslInstance {
            name,
            is_running: true,
            wsl_version: 0,
            ip: None,
            all_ips: Vec::new(),
            mac: String::new(),
            is_default: false,
            linux_hostname: String::new(),
            os_pretty_name: String::new(),
            os_id: String::new(),
            os_version: String::new(),
            kernel: String::new(),
        })
        .collect()
}

// ─── Method 2: hostname -I (fallback IP) ────────────────────────────────────

fn get_wsl_ip_hostname(distro: &str) -> Option<Ipv4Addr> {
    let output = Command::new("wsl")
        .args(["-d", distro, "--", "hostname", "-I"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.trim().split_whitespace()
                .find_map(|s| s.parse::<Ipv4Addr>().ok())
        }
        _ => None,
    }
}

// ─── Method 3: /etc/os-release ──────────────────────────────────────────────

/// Returns (pretty_name, os_id, os_version).
fn get_os_release(distro: &str) -> (String, String, String) {
    let output = Command::new("wsl")
        .args(["-d", distro, "--", "cat", "/etc/os-release"])
        .output();

    let text = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return (String::new(), String::new(), String::new()),
    };

    let mut pretty_name = String::new();
    let mut os_id = String::new();
    let mut os_version = String::new();

    for line in text.lines() {
        if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
            pretty_name = val.trim_matches('"').to_string();
        } else if let Some(val) = line.strip_prefix("ID=") {
            os_id = val.trim_matches('"').to_string();
        } else if let Some(val) = line.strip_prefix("VERSION_ID=") {
            os_version = val.trim_matches('"').to_string();
        }
    }

    (pretty_name, os_id, os_version)
}

// ─── Method 4: ip addr show eth0 ───────────────────────────────────────────

/// Parse `ip addr show eth0` for all IPv4 addresses and MAC.
/// Returns (all_ipv4s, mac_address).
fn get_network_info(distro: &str) -> (Vec<Ipv4Addr>, String) {
    let output = Command::new("wsl")
        .args(["-d", distro, "--", "ip", "addr", "show", "eth0"])
        .output();

    let text = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return (Vec::new(), String::new()),
    };

    let mut ips = Vec::new();
    let mut mac = String::new();

    for line in text.lines() {
        let trimmed = line.trim();
        // "inet 172.28.64.5/20 brd 172.28.79.255 scope global eth0"
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(cidr) = rest.split_whitespace().next() {
                if let Some(ip_str) = cidr.split('/').next() {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        ips.push(ip);
                    }
                }
            }
        }
        // "link/ether 00:15:5d:xx:xx:xx brd ff:ff:ff:ff:ff:ff"
        if let Some(rest) = trimmed.strip_prefix("link/ether ") {
            if let Some(m) = rest.split_whitespace().next() {
                mac = m.to_uppercase();
            }
        }
    }

    (ips, mac)
}

// ─── Method 5: uname -r ────────────────────────────────────────────────────

fn get_kernel(distro: &str) -> String {
    let output = Command::new("wsl")
        .args(["-d", distro, "--", "uname", "-r"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }
        _ => String::new(),
    }
}

// ─── Method 6: hostname ────────────────────────────────────────────────────

fn get_linux_hostname(distro: &str) -> String {
    let output = Command::new("wsl")
        .args(["-d", distro, "--", "cat", "/etc/hostname"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        }
        _ => String::new(),
    }
}

// ─── UTF-16LE decoder ───────────────────────────────────────────────────────

/// Decode WSL CLI output which is often UTF-16LE on Windows.
fn decode_wsl_output(bytes: &[u8]) -> String {
    // Check for UTF-16LE BOM
    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
        let u16s: Vec<u16> = bytes[2..].chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }

    // Heuristic: if every other byte is 0, it's likely UTF-16LE without BOM
    if bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0 {
        let u16s: Vec<u16> = bytes.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        return String::from_utf16_lossy(&u16s);
    }

    String::from_utf8_lossy(bytes).to_string()
}
