use std::collections::HashMap;

use chrono::Local;

use crate::types::*;

/// Info tracked per connection across ticks.
#[derive(Clone)]
struct ConnInfo {
    state: Option<TcpState>,
    process_name: String,
    proto: ConnProto,
    outbound: bool,
    dns_name: Option<String>,
}

/// Tracks connection state across ticks and produces traffic events.
pub struct TrafficTracker {
    /// Previous tick's connections.
    prev_connections: HashMap<ConnKey, ConnInfo>,
    /// Log of traffic events (newest at the end).
    pub log: Vec<TrafficEntry>,
    /// Max events to keep in log.
    pub max_log_size: usize,
    /// Whether to auto-scroll to bottom.
    pub auto_scroll: bool,
    /// Current scroll offset in the log.
    pub scroll_offset: usize,
    /// Filter: only show events matching this text.
    pub filter_text: String,
    /// Pause live capture.
    pub paused: bool,
    /// Per-connection cumulative data estimate (bytes), keyed by ConnKey.
    pub conn_data: HashMap<ConnKey, u64>,
    /// Hide localhost/loopback connections in traffic view.
    pub hide_localhost: bool,
}

impl TrafficTracker {
    pub fn new(max_log_size: usize) -> Self {
        Self {
            prev_connections: HashMap::new(),
            log: Vec::with_capacity(max_log_size),
            max_log_size,
            auto_scroll: true,
            scroll_offset: 0,
            filter_text: String::new(),
            paused: false,
            conn_data: HashMap::new(),
            hide_localhost: true, // Hide localhost by default — show real traffic
        }
    }

    /// Compare current connections to previous state and generate events.
    pub fn update(&mut self, connections: &[Connection], dns_cache: &DnsCache) {
        if self.paused {
            return;
        }

        let now = Local::now().time();
        let mut current: HashMap<ConnKey, ConnInfo> = HashMap::with_capacity(connections.len());

        for conn in connections {
            // Skip LISTEN and UDP binds for traffic tracking — they're static noise
            if matches!(conn.state.as_ref(), Some(TcpState::Listen)) {
                continue;
            }
            // Skip UDP sockets with no remote address — they're just bound sockets,
            // not actual traffic events (UDP is connectionless, OS can't track remotes)
            if conn.proto == ConnProto::Udp && conn.remote_addr.is_none() {
                continue;
            }
            let key = conn.key();
            let outbound = conn.is_outbound();

            // Look up DNS from cache
            let dns_name = conn.remote_addr
                .and_then(|ip| dns_cache.get(&ip).cloned().flatten());

            current.insert(key, ConnInfo {
                state: conn.state.clone(),
                process_name: conn.process_name.clone(),
                proto: conn.proto.clone(),
                outbound,
                dns_name,
            });
        }

        // Detect new connections
        for conn in connections {
            if matches!(conn.state.as_ref(), Some(TcpState::Listen)) {
                continue;
            }
            // Skip UDP binds (no remote endpoint) — same as above
            if conn.proto == ConnProto::Udp && conn.remote_addr.is_none() {
                continue;
            }
            let key = conn.key();
            let dns_name = conn.remote_addr
                .and_then(|ip| dns_cache.get(&ip).cloned().flatten());

            if !self.prev_connections.contains_key(&key) {
                self.push_event(TrafficEntry {
                    timestamp: now,
                    event: TrafficEventKind::NewConnection,
                    proto: conn.proto.clone(),
                    local_addr: conn.local_addr,
                    local_port: conn.local_port,
                    remote_addr: conn.remote_addr,
                    remote_port: conn.remote_port,
                    process_name: conn.process_name.clone(),
                    outbound: conn.is_outbound(),
                    state_label: conn.state.as_ref().map(|s| s.label().to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    dns_name: dns_name.clone(),
                    data_size: None,
                });
            } else if let Some(prev) = self.prev_connections.get(&key) {
                // Detect state changes
                if let (Some(ps), Some(cs)) = (&prev.state, &conn.state) {
                    if ps != cs {
                        let data = self.conn_data.get(&key).copied();
                        self.push_event(TrafficEntry {
                            timestamp: now,
                            event: TrafficEventKind::StateChange {
                                from: ps.clone(),
                                to: cs.clone(),
                            },
                            proto: conn.proto.clone(),
                            local_addr: conn.local_addr,
                            local_port: conn.local_port,
                            remote_addr: conn.remote_addr,
                            remote_port: conn.remote_port,
                            process_name: conn.process_name.clone(),
                            outbound: conn.is_outbound(),
                            state_label: cs.label().to_string(),
                            dns_name: dns_name.clone(),
                            data_size: data,
                        });
                    }
                }
            }
        }

        // Detect closed connections — collect first to avoid borrow conflict
        let closed_events: Vec<TrafficEntry> = self.prev_connections.iter()
            .filter(|(key, _)| !current.contains_key(key))
            .map(|(key, info)| {
                let data = self.conn_data.get(key).copied();
                TrafficEntry {
                    timestamp: now,
                    event: TrafficEventKind::ConnectionClosed,
                    proto: info.proto.clone(),
                    local_addr: key.local_addr,
                    local_port: key.local_port,
                    remote_addr: key.remote_addr,
                    remote_port: key.remote_port,
                    process_name: info.process_name.clone(),
                    outbound: info.outbound,
                    state_label: info.state.as_ref().map(|s| s.label().to_string())
                        .unwrap_or_else(|| "CLOSED".to_string()),
                    dns_name: info.dns_name.clone(),
                    data_size: data,
                }
            })
            .collect();

        // Remove closed connection data tracking
        let closed_keys: Vec<ConnKey> = self.prev_connections.keys()
            .filter(|key| !current.contains_key(key))
            .cloned()
            .collect();
        for key in &closed_keys {
            self.conn_data.remove(key);
        }

        for entry in closed_events {
            self.push_event(entry);
        }

        self.prev_connections = current;
    }

    fn push_event(&mut self, entry: TrafficEntry) {
        self.log.push(entry);
        if self.log.len() > self.max_log_size {
            self.log.drain(0..self.log.len() - self.max_log_size);
        }
        if self.auto_scroll {
            self.scroll_offset = self.log.len();
        }
    }

    pub fn filtered_log(&self) -> Vec<&TrafficEntry> {
        if self.filter_text.is_empty() {
            self.log.iter().collect()
        } else {
            let ft = self.filter_text.to_lowercase();
            self.log
                .iter()
                .filter(|e| {
                    e.process_name.to_lowercase().contains(&ft)
                        || e.proto.label().to_lowercase().contains(&ft)
                        || e.local_addr.to_string().contains(&ft)
                        || e.local_port.to_string().contains(&ft)
                        || e.remote_addr.map(|a| a.to_string().contains(&ft)).unwrap_or(false)
                        || e.remote_port.map(|p| p.to_string().contains(&ft)).unwrap_or(false)
                        || e.event.label().to_lowercase().contains(&ft)
                        || e.state_label.to_lowercase().contains(&ft)
                        || e.dns_name.as_ref().map(|n| n.to_lowercase().contains(&ft)).unwrap_or(false)
                })
                .collect()
        }
    }

    pub fn clear(&mut self) {
        self.log.clear();
        self.scroll_offset = 0;
    }
}
