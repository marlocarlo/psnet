//! Per-application bandwidth tracking.
//!
//! Tracks download/upload bytes per process by correlating packet sniffer
//! data with the connection table. Maintains rolling speed samples for
//! mini-sparklines per application.

use std::collections::HashMap;

use chrono::Local;

use crate::types::{AppBandwidth, Connection, ConnProto, PacketSnippet, PacketDirection, TcpState};

/// Tracks bandwidth usage per application process.
pub struct BandwidthTracker {
    /// Per-app cumulative bandwidth. Key = lowercase process name.
    pub apps: HashMap<String, AppBandwidth>,
    /// Bytes-per-tick accumulator for speed calculation.
    tick_down: HashMap<String, u64>,
    tick_up: HashMap<String, u64>,
    /// Sort column for UI.
    pub sort_column: usize,
    pub sort_ascending: bool,
}

impl BandwidthTracker {
    pub fn new() -> Self {
        Self {
            apps: HashMap::new(),
            tick_down: HashMap::new(),
            tick_up: HashMap::new(),
            sort_column: 0, // Total bytes
            sort_ascending: false,
        }
    }

    /// Ingest sniffer packets to attribute bandwidth to processes.
    /// Matches packets against the connection table to resolve process ownership.
    pub fn ingest_packets(
        &mut self,
        packets: &[PacketSnippet],
        connections: &[Connection],
    ) {
        // Build a fast lookup: (local_port, remote_port, proto) -> process_name
        let mut port_proc: HashMap<(u16, u16, bool), &str> = HashMap::with_capacity(connections.len());
        for conn in connections {
            if matches!(conn.state.as_ref(), Some(TcpState::Listen)) {
                continue;
            }
            let is_tcp = conn.proto == ConnProto::Tcp;
            let rp = conn.remote_port.unwrap_or(0);
            if !conn.process_name.is_empty() {
                port_proc.insert((conn.local_port, rp, is_tcp), &conn.process_name);
                // Also insert reverse for inbound matching
                if rp > 0 {
                    port_proc.insert((rp, conn.local_port, is_tcp), &conn.process_name);
                }
            }
        }

        for pkt in packets {
            let is_tcp = pkt.protocol == ConnProto::Tcp;
            let inbound = pkt.direction == PacketDirection::Inbound;

            // Try to find owning process
            let process_name = port_proc
                .get(&(pkt.src_port, pkt.dst_port, is_tcp))
                .or_else(|| port_proc.get(&(pkt.dst_port, pkt.src_port, is_tcp)))
                .map(|s| s.to_string())
                .unwrap_or_default();

            if process_name.is_empty() || process_name.starts_with("PID:") {
                continue;
            }

            let key = process_name.to_lowercase();
            let bytes = pkt.payload_size as u64;

            if inbound {
                *self.tick_down.entry(key.clone()).or_insert(0) += bytes;
            } else {
                *self.tick_up.entry(key.clone()).or_insert(0) += bytes;
            }

            let app = self.apps.entry(key).or_insert_with(|| AppBandwidth::new(process_name.clone()));
            if inbound {
                app.download_bytes += bytes;
            } else {
                app.upload_bytes += bytes;
            }
            app.last_seen = Local::now().time();
        }
    }

    /// Estimate per-app bandwidth from the connection table when the sniffer
    /// is not capturing packets (non-admin). Distributes system-wide speed
    /// proportionally by active connection count per process.
    pub fn estimate_from_connections(
        &mut self,
        connections: &[Connection],
        total_down_bps: f64,
        total_up_bps: f64,
    ) {
        // Only estimate if sniffer produced nothing this tick
        if !self.tick_down.is_empty() || !self.tick_up.is_empty() {
            return;
        }

        // Count established connections per process
        let mut conn_counts: HashMap<String, usize> = HashMap::new();
        let mut total_active = 0usize;
        for conn in connections {
            if !matches!(conn.state.as_ref(), Some(TcpState::Established)) {
                continue;
            }
            if conn.process_name.is_empty() || conn.process_name.starts_with("PID:") {
                continue;
            }
            let key = conn.process_name.to_lowercase();
            *conn_counts.entry(key).or_insert(0) += 1;
            total_active += 1;
        }

        if total_active == 0 || (total_down_bps < 100.0 && total_up_bps < 100.0) {
            return;
        }

        // Distribute bandwidth proportionally
        for (key, count) in &conn_counts {
            let fraction = *count as f64 / total_active as f64;
            let down = (total_down_bps * fraction) as u64;
            let up = (total_up_bps * fraction) as u64;

            // Find original-case process name from connections
            let display_name = connections.iter()
                .find(|c| c.process_name.to_lowercase() == *key)
                .map(|c| c.process_name.clone())
                .unwrap_or_else(|| key.clone());

            let app = self.apps.entry(key.clone())
                .or_insert_with(|| AppBandwidth::new(display_name));
            app.download_bytes += down;
            app.upload_bytes += up;
            app.last_seen = Local::now().time();

            *self.tick_down.entry(key.clone()).or_insert(0) += down;
            *self.tick_up.entry(key.clone()).or_insert(0) += up;
        }
    }

    /// Update active connection counts and flush tick speed data.
    /// Call once per tick after ingest_packets.
    pub fn finish_tick(&mut self, connections: &[Connection]) {
        // Count active connections per process
        let mut conn_counts: HashMap<String, usize> = HashMap::new();
        for conn in connections {
            if matches!(conn.state.as_ref(), Some(TcpState::Listen) | Some(TcpState::Closed)) {
                continue;
            }
            if !conn.process_name.is_empty() {
                *conn_counts.entry(conn.process_name.to_lowercase()).or_insert(0) += 1;
            }
        }

        // Update connection counts and push speed samples.
        // When an app had no measured traffic this tick but still has active
        // connections, decay the previous value instead of slamming to 0.
        // This prevents all rows flickering to "idle" when the sniffer
        // produces no packets for a few consecutive ticks.
        for (key, app) in &mut self.apps {
            app.active_connections = conn_counts.get(key).copied().unwrap_or(0);

            let has_tick_data = self.tick_down.contains_key(key) || self.tick_up.contains_key(key);
            let down = self.tick_down.get(key).copied().unwrap_or(0) as f64;
            let up = self.tick_up.get(key).copied().unwrap_or(0) as f64;

            let (push_down, push_up) = if has_tick_data {
                // Real data this tick — use it directly
                (down, up)
            } else if app.active_connections > 0 {
                // No data this tick but app has active connections — decay previous
                let prev_d = app.recent_down.back().copied().unwrap_or(0.0);
                let prev_u = app.recent_up.back().copied().unwrap_or(0.0);
                (prev_d * 0.6, prev_u * 0.6)
            } else {
                // No connections — truly idle
                (0.0, 0.0)
            };

            app.recent_down.push_back(push_down);
            app.recent_up.push_back(push_up);
            if app.recent_down.len() > 20 {
                app.recent_down.pop_front();
            }
            if app.recent_up.len() > 20 {
                app.recent_up.pop_front();
            }
        }

        self.tick_down.clear();
        self.tick_up.clear();
    }

    /// Get apps sorted for display.
    pub fn sorted_apps(&self) -> Vec<&AppBandwidth> {
        let mut apps: Vec<&AppBandwidth> = self.apps.values().collect();
        let col = self.sort_column;
        let asc = self.sort_ascending;

        apps.sort_by(|a, b| {
            let ord = match col {
                0 => b.total_bytes().cmp(&a.total_bytes()),
                1 => b.download_bytes.cmp(&a.download_bytes),
                2 => b.upload_bytes.cmp(&a.upload_bytes),
                3 => b.active_connections.cmp(&a.active_connections),
                // Case-insensitive without allocation
                4 => a.process_name.bytes().map(|b| b.to_ascii_lowercase())
                    .cmp(b.process_name.bytes().map(|b| b.to_ascii_lowercase())),
                _ => std::cmp::Ordering::Equal,
            };
            if asc { ord.reverse() } else { ord }
        });
        apps
    }

    /// Get current tick's download bytes for a process.
    pub fn current_down_speed(&self, key: &str) -> f64 {
        self.apps.get(key)
            .and_then(|a| a.recent_down.back().copied())
            .unwrap_or(0.0)
    }

    /// Get current tick's upload bytes for a process.
    pub fn current_up_speed(&self, key: &str) -> f64 {
        self.apps.get(key)
            .and_then(|a| a.recent_up.back().copied())
            .unwrap_or(0.0)
    }
}
