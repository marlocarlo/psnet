//! WSL (Windows Subsystem for Linux) instance discovery.
//!
//! Detects running WSL distros and resolves their IP addresses.
//! Silently returns empty if WSL is not installed.

use std::net::Ipv4Addr;
use std::process::Command;

/// A discovered WSL instance.
#[derive(Clone, Debug)]
pub struct WslInstance {
    pub name: String,
    pub is_running: bool,
    pub ip: Option<Ipv4Addr>,
}

/// Discover running WSL instances and their IPs.
pub fn discover() -> Vec<WslInstance> {
    let output = Command::new("wsl")
        .args(["--list", "--running", "--quiet"])
        .output();

    let output = match output {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = decode_wsl_output(&output.stdout);
    let mut instances = Vec::new();

    for name in stdout.lines() {
        let name = name.trim().to_string();
        if name.is_empty() { continue; }

        let ip = get_wsl_ip(&name);
        instances.push(WslInstance {
            name,
            is_running: true,
            ip,
        });
    }

    instances
}

/// Get the IP of a specific WSL distro by running `hostname -I` inside it.
fn get_wsl_ip(distro: &str) -> Option<Ipv4Addr> {
    let output = Command::new("wsl")
        .args(["-d", distro, "--", "hostname", "-I"])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            stdout.trim().split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
        }
        _ => None,
    }
}

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
