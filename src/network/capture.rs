use std::collections::HashMap;

use crate::types::*;

/// Info tracked per connection across ticks.
#[derive(Clone)]
struct ConnInfo {
    state: Option<TcpState>,
}

/// Tracks connection state across ticks and produces traffic events.
pub struct TrafficTracker {
    /// Previous tick's connections.
    prev_connections: HashMap<ConnKey, ConnInfo>,
    /// Log of traffic events (newest at the end).
    pub log: Vec<TrafficEntry>,
    /// Max events to keep in log.
    pub max_log_size: usize,
    /// Pause live capture.
    pub paused: bool,
}

impl TrafficTracker {
    pub fn new(max_log_size: usize) -> Self {
        Self {
            prev_connections: HashMap::new(),
            log: Vec::with_capacity(max_log_size),
            max_log_size,
            paused: false,
        }
    }

    /// Compare current connections to previous state and generate events.
    pub fn update(&mut self, connections: &[Connection], _dns_cache: &DnsCache) {
        if self.paused {
            return;
        }

        let mut current: HashMap<ConnKey, ConnInfo> = HashMap::with_capacity(connections.len());

        for conn in connections {
            if matches!(conn.state.as_ref(), Some(TcpState::Listen)) {
                continue;
            }
            if conn.proto == ConnProto::Udp && conn.remote_addr.is_none() {
                continue;
            }
            let key = conn.key();
            current.insert(key, ConnInfo {
                state: conn.state.clone(),
            });
        }

        // Detect new connections
        for conn in connections {
            if matches!(conn.state.as_ref(), Some(TcpState::Listen)) {
                continue;
            }
            if conn.proto == ConnProto::Udp && conn.remote_addr.is_none() {
                continue;
            }
            let key = conn.key();

            if !self.prev_connections.contains_key(&key) {
                self.push_event(TrafficEntry {
                    event: TrafficEventKind::NewConnection,
                });
            } else if let Some(prev) = self.prev_connections.get(&key) {
                if let (Some(ps), Some(cs)) = (&prev.state, &conn.state) {
                    if ps != cs {
                        self.push_event(TrafficEntry {
                            event: TrafficEventKind::StateChange,
                        });
                    }
                }
            }
        }

        // Detect closed connections
        let closed_count = self.prev_connections.keys()
            .filter(|key| !current.contains_key(key))
            .count();
        for _ in 0..closed_count {
            self.push_event(TrafficEntry {
                event: TrafficEventKind::ConnectionClosed,
            });
        }

        self.prev_connections = current;
    }

    fn push_event(&mut self, entry: TrafficEntry) {
        self.log.push(entry);
        if self.log.len() > self.max_log_size {
            self.log.drain(0..self.log.len() - self.max_log_size);
        }
    }

    /// Ingest sniffer packets as DATA events in the traffic log.
    pub fn ingest_packets(&mut self, packets: &[PacketSnippet], _connections: &[Connection], _dns_cache: &DnsCache) {
        if self.paused {
            return;
        }
        for _pkt in packets {
            self.push_event(TrafficEntry {
                event: TrafficEventKind::DataActivity,
            });
        }
    }
}
