use std::time::Instant;

use crossterm::event::KeyCode;
use sysinfo::Networks;

use crate::network::capture::TrafficTracker;
use crate::network::connections::fetch_connections;
use crate::network::dns;
use crate::network::sniffer::PacketSniffer;
use crate::network::speed::get_network_bytes;
use crate::types::*;

/// Application state — owns all data, updated each tick.
pub struct App {
    // Speed monitoring
    pub speed_history: SpeedHistory,
    pub current_down_speed: f64,
    pub current_up_speed: f64,
    pub peak_down: f64,
    pub peak_up: f64,
    pub total_down: u64,
    pub total_up: u64,
    pub interface_name: String,
    prev_bytes_recv: u64,
    prev_bytes_sent: u64,
    prev_time: Instant,

    // Connections tab
    pub connections: Vec<Connection>,
    pub conn_scroll: usize,
    pub sort_column: usize,
    pub sort_ascending: bool,
    pub show_listen: bool,
    pub filter_text: String,

    // Traffic tab
    pub traffic_tracker: TrafficTracker,

    // UI state
    pub bottom_tab: BottomTab,
    pub session_start: Instant,
    /// Hide localhost connections in Connections tab.
    pub hide_localhost_conn: bool,

    // Packet sniffer (wire preview)
    pub sniffer: PacketSniffer,

    // Internal
    pid_cache: PidCache,
    pub dns_cache: DnsCache,
    dns_tick: u32,
}

impl App {
    pub fn new(networks: &Networks) -> Self {
        let (recv, sent, iface) = get_network_bytes(networks);
        Self {
            speed_history: SpeedHistory::new(60),
            current_down_speed: 0.0,
            current_up_speed: 0.0,
            peak_down: 0.0,
            peak_up: 0.0,
            total_down: 0,
            total_up: 0,
            interface_name: iface,
            prev_bytes_recv: recv,
            prev_bytes_sent: sent,
            prev_time: Instant::now(),

            connections: Vec::new(),
            conn_scroll: 0,
            sort_column: 5, // Default sort by State
            sort_ascending: true, // ESTABLISHED first (rank 0)
            show_listen: true,
            filter_text: String::new(),

            traffic_tracker: TrafficTracker::new(5000),

            bottom_tab: BottomTab::Traffic,
            session_start: Instant::now(),
            hide_localhost_conn: true,

            sniffer: {
                let mut s = PacketSniffer::new(200);
                s.start();
                s
            },

            pid_cache: PidCache::new(),
            dns_cache: DnsCache::new(),
            dns_tick: 0,
        }
    }

    /// Refresh network speed and connections. Called each tick.
    pub fn update(&mut self, networks: &mut Networks) {
        networks.refresh();
        let (recv, sent, iface) = get_network_bytes(networks);
        let now = Instant::now();
        let elapsed = now.duration_since(self.prev_time).as_secs_f64();

        if elapsed > 0.0 {
            let dr = recv.saturating_sub(self.prev_bytes_recv) as f64;
            let ds = sent.saturating_sub(self.prev_bytes_sent) as f64;
            self.current_down_speed = dr / elapsed;
            self.current_up_speed = ds / elapsed;

            self.total_down += recv.saturating_sub(self.prev_bytes_recv);
            self.total_up += sent.saturating_sub(self.prev_bytes_sent);

            if self.current_down_speed > self.peak_down {
                self.peak_down = self.current_down_speed;
            }
            if self.current_up_speed > self.peak_up {
                self.peak_up = self.current_up_speed;
            }

            self.speed_history.push(self.current_down_speed, self.current_up_speed);
        }

        self.prev_bytes_recv = recv;
        self.prev_bytes_sent = sent;
        self.prev_time = now;
        self.interface_name = iface;

        // Fetch connections
        self.connections = fetch_connections(&mut self.pid_cache);

        // Resolve DNS for remote addresses
        self.resolve_dns();

        self.sort_connections();

        // Update traffic tracker
        self.traffic_tracker.update(&self.connections, &self.dns_cache);
    }

    // ─── DNS resolution ───────────────────────────────────────────────

    /// Read DNS cache from OS and apply hostnames to connections.
    fn resolve_dns(&mut self) {
        // Read from OS DNS cache every tick (API call is fast)
        let os_cache = dns::read_dns_cache_api();
        for (ip, hostname) in &os_cache {
            self.dns_cache.entry(*ip).or_insert_with(|| Some(hostname.clone()));
        }

        // Supplement with ipconfig parsing every 10 ticks (~10s, it spawns a process)
        if self.dns_tick % 10 == 0 {
            let ipconfig_cache = dns::read_dns_cache_ipconfig();
            for (ip, hostname) in ipconfig_cache {
                self.dns_cache.entry(ip).or_insert_with(|| Some(hostname));
            }
        }
        self.dns_tick = self.dns_tick.wrapping_add(1);

        // Apply cached DNS names to connections
        for conn in &mut self.connections {
            if let Some(remote_ip) = conn.remote_addr {
                if remote_ip.is_unspecified() {
                    continue;
                }
                if remote_ip.is_loopback() {
                    conn.dns_hostname = Some("localhost".to_string());
                    continue;
                }
                if let Some(cached) = self.dns_cache.get(&remote_ip) {
                    conn.dns_hostname = cached.clone();
                }
            }
        }
    }

    // ─── Sorting ─────────────────────────────────────────────────────────

    pub fn sort_connections(&mut self) {
        let col = self.sort_column;
        let asc = self.sort_ascending;
        self.connections.sort_by(|a, b| {
            let ord = match col {
                0 => a.proto.label().cmp(b.proto.label()),
                1 => a.local_addr.to_string().cmp(&b.local_addr.to_string()),
                2 => a.local_port.cmp(&b.local_port),
                3 => {
                    let ra = a.remote_addr.map(|i| i.to_string()).unwrap_or_default();
                    let rb = b.remote_addr.map(|i| i.to_string()).unwrap_or_default();
                    ra.cmp(&rb)
                }
                4 => a.remote_port.unwrap_or(0).cmp(&b.remote_port.unwrap_or(0)),
                5 => {
                    // Custom state ordering: ESTABLISHED first, then active, then passive
                    fn state_rank(s: Option<&TcpState>) -> u8 {
                        match s {
                            Some(TcpState::Established) => 0,
                            Some(TcpState::SynSent) => 1,
                            Some(TcpState::SynReceived) => 2,
                            Some(TcpState::CloseWait) => 3,
                            Some(TcpState::FinWait1) => 4,
                            Some(TcpState::FinWait2) => 5,
                            Some(TcpState::Closing) => 6,
                            Some(TcpState::LastAck) => 7,
                            Some(TcpState::TimeWait) => 8,
                            Some(TcpState::Listen) => 9,
                            Some(TcpState::Closed) => 10,
                            Some(TcpState::DeleteTcb) => 11,
                            Some(TcpState::Unknown(_)) => 12,
                            None => 13, // UDP
                        }
                    }
                    state_rank(a.state.as_ref()).cmp(&state_rank(b.state.as_ref()))
                }
                6 => a.process_name.to_lowercase().cmp(&b.process_name.to_lowercase()),
                _ => std::cmp::Ordering::Equal,
            };
            if asc { ord } else { ord.reverse() }
        });
    }

    pub fn toggle_sort(&mut self, col: usize) {
        if self.sort_column == col {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = col;
            self.sort_ascending = true;
        }
        self.sort_connections();
    }

    // ─── Filtering ───────────────────────────────────────────────────────

    pub fn filtered_connections(&self) -> Vec<&Connection> {
        self.connections.iter().filter(|c| {
            // Hide localhost ↔ localhost connections when enabled
            if self.hide_localhost_conn {
                if c.local_addr.is_loopback()
                    && c.remote_addr.map(|a| a.is_loopback()).unwrap_or(false)
                {
                    return false;
                }
            }
            if !self.show_listen {
                if matches!(c.state.as_ref(), Some(TcpState::Listen)) {
                    return false;
                }
            }
            if !self.filter_text.is_empty() {
                let ft = self.filter_text.to_lowercase();
                return c.process_name.to_lowercase().contains(&ft)
                    || c.local_addr.to_string().contains(&ft)
                    || c.local_port.to_string().contains(&ft)
                    || c.remote_addr.map(|a| a.to_string().contains(&ft)).unwrap_or(false)
                    || c.remote_port.map(|p| p.to_string().contains(&ft)).unwrap_or(false)
                    || c.state.as_ref().map(|s| s.label().to_lowercase().contains(&ft)).unwrap_or(false)
                    || c.proto.label().to_lowercase().contains(&ft)
                    || c.dns_hostname.as_ref().map(|n| n.to_lowercase().contains(&ft)).unwrap_or(false);
            }
            true
        }).collect()
    }

    // ─── Input handling ──────────────────────────────────────────────────

    /// Handle a key press. Returns true if the app should quit.
    pub fn handle_key(&mut self, code: KeyCode) -> bool {
        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => return true,
            KeyCode::Tab => {
                self.bottom_tab = self.bottom_tab.next();
            }
            KeyCode::Up => self.scroll_up(1),
            KeyCode::Down => self.scroll_down(1),
            KeyCode::PageUp => self.scroll_up(20),
            KeyCode::PageDown => self.scroll_down(20),
            KeyCode::Home => self.scroll_home(),
            KeyCode::End => self.scroll_end(),
            _ => {
                match self.bottom_tab {
                    BottomTab::Connections => self.handle_connections_key(code),
                    BottomTab::Traffic => self.handle_traffic_key(code),
                }
            }
        }
        false
    }

    fn handle_connections_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('l') | KeyCode::Char('L') => {
                self.show_listen = !self.show_listen;
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                self.hide_localhost_conn = !self.hide_localhost_conn;
            }
            // Sort keys mapped to displayed column order:
            // 1=Process, 2=Remote Host, 3=Service, 4=State, 5=Local
            KeyCode::Char('1') => self.toggle_sort(6),
            KeyCode::Char('2') => self.toggle_sort(3),
            KeyCode::Char('3') => self.toggle_sort(4),
            KeyCode::Char('4') => self.toggle_sort(5),
            KeyCode::Char('5') => self.toggle_sort(2),
            KeyCode::Backspace => { self.filter_text.pop(); }
            KeyCode::Esc => { self.filter_text.clear(); }
            KeyCode::Char(c) => {
                if c == 'f' || c == 'F' {
                    // 'f' starts filter mode
                } else {
                    self.filter_text.push(c);
                }
            }
            _ => {}
        }
    }

    fn handle_traffic_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('p') | KeyCode::Char('P') => {
                self.traffic_tracker.paused = !self.traffic_tracker.paused;
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                self.traffic_tracker.clear();
            }
            KeyCode::Char('x') | KeyCode::Char('X') => {
                self.traffic_tracker.hide_localhost = !self.traffic_tracker.hide_localhost;
            }
            KeyCode::Backspace => { self.traffic_tracker.filter_text.pop(); }
            KeyCode::Esc => { self.traffic_tracker.filter_text.clear(); }
            KeyCode::Char(c) => {
                self.traffic_tracker.filter_text.push(c);
            }
            _ => {}
        }
    }

    fn scroll_up(&mut self, n: usize) {
        match self.bottom_tab {
            BottomTab::Connections => {
                self.conn_scroll = self.conn_scroll.saturating_sub(n);
            }
            BottomTab::Traffic => {
                self.traffic_tracker.auto_scroll = false;
                self.traffic_tracker.scroll_offset =
                    self.traffic_tracker.scroll_offset.saturating_sub(n);
            }
        }
    }

    fn scroll_down(&mut self, n: usize) {
        match self.bottom_tab {
            BottomTab::Connections => {
                self.conn_scroll += n;
            }
            BottomTab::Traffic => {
                self.traffic_tracker.scroll_offset += n;
                let max = self.traffic_tracker.log.len();
                if self.traffic_tracker.scroll_offset >= max {
                    self.traffic_tracker.auto_scroll = true;
                }
            }
        }
    }

    fn scroll_home(&mut self) {
        match self.bottom_tab {
            BottomTab::Connections => self.conn_scroll = 0,
            BottomTab::Traffic => {
                self.traffic_tracker.auto_scroll = false;
                self.traffic_tracker.scroll_offset = 0;
            }
        }
    }

    fn scroll_end(&mut self) {
        match self.bottom_tab {
            BottomTab::Connections => self.conn_scroll = self.connections.len(),
            BottomTab::Traffic => {
                self.traffic_tracker.auto_scroll = true;
                self.traffic_tracker.scroll_offset = self.traffic_tracker.log.len();
            }
        }
    }
}
