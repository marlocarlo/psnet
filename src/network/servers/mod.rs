pub mod types;
pub mod listeners;
pub mod fingerprint;
pub mod fingerprints;
pub mod classify;
pub mod wappalyzer_db;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::Instant;

use chrono::Local;

use types::{ListeningPort, ServerKind, ListenProto};
use listeners::{RawListener, ProcessInfo};
use fingerprint::ProbeResult;

// ─── Summary ────────────────────────────────────────────────────────────────

pub struct ServersSummary {
    pub total: usize,
    pub tcp: usize,
    pub udp: usize,
    pub responsive: usize,
    pub categories: usize,
}

// ─── ServersScanner ─────────────────────────────────────────────────────────

/// Servers scanner — detects and fingerprints all listening services on this PC.
pub struct ServersScanner {
    /// Current list of detected servers/listeners, sorted by priority.
    pub servers: Vec<ListeningPort>,
    /// Whether a scan is in progress.
    scanning: Arc<AtomicBool>,
    /// Background scan results buffer.
    pending: Arc<Mutex<Option<Vec<ListeningPort>>>>,
    /// Last scan time.
    pub last_scan: Option<Instant>,
    /// Scan interval counter.
    scan_tick: u32,
    /// Filter text for the UI.
    pub filter_text: String,
    /// Selected row index.
    pub scroll_offset: usize,
    /// Sort column.
    pub sort_column: usize,
    /// Sort ascending.
    pub sort_ascending: bool,
}

impl ServersScanner {
    pub fn new() -> Self {
        // Do an immediate synchronous quick scan (listeners only, no probing)
        // so the tab has data instantly.
        let servers = quick_scan();

        Self {
            servers,
            scanning: Arc::new(AtomicBool::new(false)),
            pending: Arc::new(Mutex::new(None)),
            last_scan: None,
            scan_tick: 0,
            filter_text: String::new(),
            scroll_offset: 0,
            sort_column: 0,
            sort_ascending: true,
        }
    }

    /// Start a full background scan (enumerate + probe + classify).
    pub fn start_scan(&self) {
        if self.scanning.swap(true, Ordering::SeqCst) {
            return; // Already scanning
        }

        let scanning = Arc::clone(&self.scanning);
        let pending = Arc::clone(&self.pending);

        thread::spawn(move || {
            let result = full_scan();
            if let Ok(mut p) = pending.lock() {
                *p = Some(result);
            }
            scanning.store(false, Ordering::SeqCst);
        });
    }

    /// Called each tick. Auto-triggers scan periodically.
    pub fn tick(&mut self) {
        self.scan_tick += 1;
        // Quick listener refresh every 5 ticks (~5 seconds)
        if self.scan_tick % 5 == 1 {
            self.quick_refresh();
        }
        // Full probe scan every 30 ticks (~30 seconds)
        if self.scan_tick % 30 == 1 {
            self.start_scan();
        }
        self.poll_results();
    }

    /// Fast refresh: just re-enumerate listeners and update connection counts.
    /// No probing — keeps existing fingerprint data.
    fn quick_refresh(&mut self) {
        let raw = listeners::enumerate_listeners();
        let pids: Vec<u32> = raw.iter().map(|r| r.pid).collect();
        let proc_info = listeners::resolve_process_info(&pids);

        // Build a lookup of existing servers by (port, proto) for preservation
        let mut existing: HashMap<(u16, ListenProto), ListeningPort> = HashMap::new();
        for s in self.servers.drain(..) {
            existing.insert((s.port, s.proto.clone()), s);
        }

        // Track which existing entries were seen this refresh
        let mut seen = HashSet::new();
        let now = Local::now().time();

        for r in &raw {
            let key = (r.port, r.proto.clone());
            seen.insert(key.clone());

            if let Some(prev) = existing.get(&key) {
                // Existing entry — keep all fingerprint data, update process info
                let mut entry = prev.clone();
                if let Some(pi) = proc_info.get(&r.pid) {
                    entry.process_name = pi.name.clone();
                    entry.exe_path = pi.exe_path.clone();
                    entry.cmdline = pi.cmdline.clone();
                }
                entry.pid = r.pid;
                entry.bind_addr = r.bind_addr;
                self.servers.push(entry);
            } else {
                // New listener — basic classification from process name + port only
                if r.port >= 49152 && r.pid == 0 {
                    continue;
                }
                let pi = proc_info.get(&r.pid);
                let name = pi.map(|p| p.name.as_str()).unwrap_or("System");
                let exe = pi.map(|p| p.exe_path.as_str()).unwrap_or("");
                let cmd = pi.map(|p| p.cmdline.as_str()).unwrap_or("");

                let (kind, version) = classify::classify(name, exe, cmd, r.port, None);

                if r.pid == 0 && kind == ServerKind::Unknown {
                    continue;
                }
                if r.pid == 4 && kind == ServerKind::Unknown {
                    continue;
                }

                self.servers.push(ListeningPort {
                    proto: r.proto.clone(),
                    bind_addr: r.bind_addr,
                    port: r.port,
                    pid: r.pid,
                    process_name: name.to_string(),
                    exe_path: exe.to_string(),
                    cmdline: cmd.to_string(),
                    server_kind: kind,
                    version,
                    http_title: None,
                    banner: None,
                    response_headers: Vec::new(),
                    active_connections: 0,
                    first_seen: now,
                    is_responsive: false,
                    details: build_details(name, exe, cmd, None),
                    detected_techs: Vec::new(),
                });
            }
        }

        // Sort by kind priority then port
        self.servers.sort_by(|a, b| {
            a.server_kind
                .sort_priority()
                .cmp(&b.server_kind.sort_priority())
                .then(a.port.cmp(&b.port))
        });
    }

    /// Poll background scan results.
    fn poll_results(&mut self) {
        if let Ok(mut p) = self.pending.lock() {
            if let Some(mut results) = p.take() {
                // Preserve first_seen from existing entries
                let existing_times: HashMap<(u16, ListenProto), chrono::NaiveTime> = self
                    .servers
                    .iter()
                    .map(|s| ((s.port, s.proto.clone()), s.first_seen))
                    .collect();

                for entry in &mut results {
                    let key = (entry.port, entry.proto.clone());
                    if let Some(&first) = existing_times.get(&key) {
                        entry.first_seen = first;
                    }
                }

                self.servers = results;
                self.last_scan = Some(Instant::now());
            }
        }
    }

    /// Is scanning in progress?
    pub fn is_scanning(&self) -> bool {
        self.scanning.load(Ordering::Relaxed)
    }

    /// Get servers filtered by current filter text.
    pub fn filtered_servers(&self) -> Vec<&ListeningPort> {
        if self.filter_text.is_empty() {
            self.servers.iter().collect()
        } else {
            let f = self.filter_text.to_lowercase();
            self.servers
                .iter()
                .filter(|s| {
                    s.process_name.to_lowercase().contains(&f)
                        || s.server_kind.label().to_lowercase().contains(&f)
                        || s.port.to_string().contains(&f)
                        || s.details.to_lowercase().contains(&f)
                        || s.exe_path.to_lowercase().contains(&f)
                })
                .collect()
        }
    }

    /// Summary stats for header display.
    pub fn summary(&self) -> ServersSummary {
        let total = self.servers.len();
        let tcp = self
            .servers
            .iter()
            .filter(|s| s.proto == ListenProto::Tcp)
            .count();
        let udp = total - tcp;
        let responsive = self.servers.iter().filter(|s| s.is_responsive).count();
        let categories: HashSet<_> = self
            .servers
            .iter()
            .map(|s| s.server_kind.category())
            .collect();
        ServersSummary {
            total,
            tcp,
            udp,
            responsive,
            categories: categories.len(),
        }
    }
}

// ─── Quick scan (synchronous, no probing) ───────────────────────────────────

/// Synchronous quick scan: enumerate listeners and classify by process name + port.
/// No network probing — returns instantly.
fn quick_scan() -> Vec<ListeningPort> {
    let now = Local::now().time();
    let raw = listeners::enumerate_listeners();

    let pids: Vec<u32> = {
        let mut p: Vec<u32> = raw.iter().map(|r| r.pid).collect();
        p.sort_unstable();
        p.dedup();
        p
    };
    let proc_info = listeners::resolve_process_info(&pids);

    let mut servers: Vec<ListeningPort> = raw
        .iter()
        .filter_map(|r| {
            if r.port >= 49152 && r.pid == 0 {
                return None;
            }

            let pi = proc_info.get(&r.pid);
            let name = pi.map(|p| p.name.as_str()).unwrap_or("System");
            let exe = pi.map(|p| p.exe_path.as_str()).unwrap_or("");
            let cmd = pi.map(|p| p.cmdline.as_str()).unwrap_or("");

            let (kind, version) = classify::classify(name, exe, cmd, r.port, None);

            if r.pid == 0 && kind == ServerKind::Unknown {
                return None;
            }
            if r.pid == 4 && kind == ServerKind::Unknown {
                return None;
            }

            Some(ListeningPort {
                proto: r.proto.clone(),
                bind_addr: r.bind_addr,
                port: r.port,
                pid: r.pid,
                process_name: name.to_string(),
                exe_path: exe.to_string(),
                cmdline: cmd.to_string(),
                server_kind: kind,
                version,
                http_title: None,
                banner: None,
                response_headers: Vec::new(),
                active_connections: 0,
                first_seen: now,
                is_responsive: false,
                details: build_details(name, exe, cmd, None),
                detected_techs: Vec::new(),
            })
        })
        .collect();

    servers.sort_by(|a, b| {
        a.server_kind
            .sort_priority()
            .cmp(&b.server_kind.sort_priority())
            .then(a.port.cmp(&b.port))
    });
    servers.dedup_by(|a, b| a.port == b.port && a.proto == b.proto);
    servers
}

// ─── Full scan (background, with probing) ───────────────────────────────────

/// Perform a complete scan: enumerate -> resolve processes -> probe -> classify.
fn full_scan() -> Vec<ListeningPort> {
    let now = Local::now().time();

    // 1. Enumerate all listeners
    let raw = listeners::enumerate_listeners();

    // 2. Resolve process info for all unique PIDs
    let unique_pids: Vec<u32> = {
        let mut pids: Vec<u32> = raw.iter().map(|r| r.pid).collect();
        pids.sort_unstable();
        pids.dedup();
        pids
    };
    let proc_info = listeners::resolve_process_info(&unique_pids);

    // 3. Probe ports (only TCP below ephemeral range, skip system noise)
    let probe_targets: Vec<(u16, std::net::IpAddr)> = raw
        .iter()
        .filter(|r| r.proto == ListenProto::Tcp)
        .filter(|r| r.port < 49152) // Skip ephemeral
        .filter(|r| !is_system_noise(r.port, r.pid))
        .map(|r| (r.port, r.bind_addr))
        .collect();
    let probes = fingerprint::probe_ports(&probe_targets);

    // 4. Build ListeningPort for each listener, classify
    let mut servers: Vec<ListeningPort> = raw
        .iter()
        .filter_map(|r| {
            // Skip ephemeral noise from PID 0
            if r.port >= 49152 && r.pid == 0 {
                return None;
            }

            let pi = proc_info.get(&r.pid);
            let name = pi.map(|p| p.name.as_str()).unwrap_or("System");
            let exe = pi.map(|p| p.exe_path.as_str()).unwrap_or("");
            let cmd = pi.map(|p| p.cmdline.as_str()).unwrap_or("");
            let probe = probes.get(&r.port);

            let (kind, version) = classify::classify(name, exe, cmd, r.port, probe);

            // Skip PID 0 / System noise unless it's a known service
            if r.pid == 0 && kind == ServerKind::Unknown {
                return None;
            }
            if r.pid == 4 && kind == ServerKind::Unknown {
                return None;
            }

            Some(ListeningPort {
                proto: r.proto.clone(),
                bind_addr: r.bind_addr,
                port: r.port,
                pid: r.pid,
                process_name: name.to_string(),
                exe_path: exe.to_string(),
                cmdline: cmd.to_string(),
                server_kind: kind,
                version,
                http_title: probe.and_then(|p| p.http_title.clone()),
                banner: probe.and_then(|p| p.banner.clone()),
                response_headers: probe
                    .map(|p| p.http_headers.clone())
                    .unwrap_or_default(),
                active_connections: 0, // filled in by UI from live connection data
                first_seen: now,
                is_responsive: probe.map(|p| p.is_responsive).unwrap_or(false),
                details: build_details(name, exe, cmd, probe),
                detected_techs: probe
                    .map(|p| wappalyzer_db::detect_from_headers(&p.http_headers, p.http_server.as_deref(), p.http_powered_by.as_deref()))
                    .unwrap_or_default(),
            })
        })
        .collect();

    // 5. Deduplicate: same port+proto, keep the one with more info (first after sort)
    servers.sort_by(|a, b| {
        a.server_kind
            .sort_priority()
            .cmp(&b.server_kind.sort_priority())
            .then(a.port.cmp(&b.port))
    });
    servers.dedup_by(|a, b| a.port == b.port && a.proto == b.proto);

    servers
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Returns true for known Windows system ports that produce noisy, uninteresting entries.
/// We skip probing these to avoid wasted connection attempts, but we still classify them.
fn is_system_noise(port: u16, pid: u32) -> bool {
    // PID 4 (System/kernel) owns HTTP.sys, SMB, WinRM, etc.
    // Only skip probing for ephemeral-range System ports (noise).
    // Well-known ports (< 49152) are worth probing even when System-owned.
    if pid == 4 && port >= 49152 {
        return true;
    }
    // Skip specific noisy system ports that never have useful probe data.
    matches!(port, 5040 | 7680)
}

/// Build a human-readable details string from process info and probe results.
fn build_details(name: &str, exe: &str, cmd: &str, probe: Option<&ProbeResult>) -> String {
    let mut parts = Vec::new();

    if !exe.is_empty() && exe != name {
        parts.push(format!("Path: {}", exe));
    }
    if !cmd.is_empty() && cmd != name && cmd != exe {
        // Truncate long cmdlines
        let display = if cmd.len() > 120 { &cmd[..120] } else { cmd };
        parts.push(format!("Cmd: {}", display));
    }
    if let Some(p) = probe {
        if let Some(ref server) = p.http_server {
            parts.push(format!("Server: {}", server));
        }
        if let Some(ref powered) = p.http_powered_by {
            parts.push(format!("Powered-By: {}", powered));
        }
        if p.tls_detected {
            parts.push("TLS: yes".to_string());
        }
    }

    parts.join(" | ")
}
