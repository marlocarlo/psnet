use std::time::Instant;

use crossterm::event::KeyCode;
use sysinfo::Networks;

use crate::network::alerts::AlertEngine;
use crate::network::bandwidth::BandwidthTracker;
use crate::network::capture::TrafficTracker;
use crate::network::connections::fetch_connections;
use crate::network::dns;
use crate::network::firewall::FirewallManager;
use crate::network::geoip::GeoIpResolver;
use crate::network::scanner::NetworkScanner;
use crate::network::sniffer::PacketSniffer;
use crate::network::speed::get_network_bytes;
use crate::network::system_monitor::SystemMonitor;
use crate::network::threats::ThreatDetector;
use crate::network::usage::UsageTracker;
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
    /// Selected row in Devices tab.
    pub device_scroll: usize,
    /// Dashboard time range selector.
    pub dashboard_time_range: DashboardTimeRange,
    /// Extended traffic history for dashboard graph.
    pub traffic_history: TrafficHistory,
    /// Connection count history for dashboard sparkline.
    pub connection_count_history: std::collections::VecDeque<u64>,

    // Packet sniffer (wire preview)
    pub sniffer: PacketSniffer,

    // ─── GlassWire-style modules ─────────────────────────────────────
    /// Per-app bandwidth tracking
    pub bandwidth_tracker: BandwidthTracker,
    /// Alert engine (security + network alerts)
    pub alert_engine: AlertEngine,
    /// LAN device scanner
    pub network_scanner: NetworkScanner,
    /// Windows Firewall manager
    pub firewall_manager: FirewallManager,
    /// Threat intelligence detector
    pub threat_detector: ThreatDetector,
    /// Data plan + usage persistence
    pub usage_tracker: UsageTracker,
    /// GeoIP country resolver
    pub geoip: GeoIpResolver,
    /// System monitor (hosts file, proxy, WiFi, app hash)
    pub system_monitor: SystemMonitor,

    // Detail popup overlay
    pub detail_popup: Option<DetailKind>,

    /// Tick counter — incremented each update, used for live pulse indicator.
    pub tick_count: u64,

    /// Selected row in Usage tab.
    pub usage_scroll: usize,

    /// Whether incognito mode is active (no disk writes).
    pub incognito: bool,
    /// Device rename state — Some(device_index) when renaming.
    pub renaming_device: Option<usize>,
    /// Text buffer for device rename.
    pub device_rename_text: String,

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

            bottom_tab: BottomTab::Dashboard,
            session_start: Instant::now(),
            hide_localhost_conn: true,
            device_scroll: 0,
            dashboard_time_range: DashboardTimeRange::Minutes5,
            traffic_history: TrafficHistory::new(86400),
            connection_count_history: std::collections::VecDeque::with_capacity(300),

            sniffer: {
                let mut s = PacketSniffer::new(200);
                s.start();
                s
            },

            // GlassWire-style modules
            bandwidth_tracker: BandwidthTracker::new(),
            alert_engine: AlertEngine::new(1000),
            network_scanner: NetworkScanner::new(),
            firewall_manager: FirewallManager::new(),
            threat_detector: ThreatDetector::new(),
            usage_tracker: UsageTracker::new(),
            geoip: GeoIpResolver::new(),
            system_monitor: SystemMonitor::new(),

            detail_popup: None,
            tick_count: 0,
            usage_scroll: 0,

            incognito: false,
            renaming_device: None,
            device_rename_text: String::new(),

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

            // Dashboard traffic history (per-second)
            self.traffic_history.push(self.current_down_speed, self.current_up_speed);
            // Connection count sparkline
            let active_conns = self.connections.iter()
                .filter(|c| matches!(c.state.as_ref(), Some(TcpState::Established)))
                .count() as u64;
            self.connection_count_history.push_back(active_conns);
            if self.connection_count_history.len() > 300 {
                self.connection_count_history.pop_front();
            }
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

        // Feed sniffer packets into traffic log as DATA events
        let new_packets = self.sniffer.drain_new();
        if !new_packets.is_empty() {
            self.traffic_tracker.ingest_packets(&new_packets, &self.connections, &self.dns_cache);
            // Per-app bandwidth tracking from sniffer data
            self.bandwidth_tracker.ingest_packets(&new_packets, &self.connections);
        }

        // ─── GlassWire-style module updates ──────────────────────────

        // Estimate per-app bandwidth from connections when sniffer has no data
        self.bandwidth_tracker.estimate_from_connections(
            &self.connections,
            self.current_down_speed,
            self.current_up_speed,
        );

        // Finish bandwidth tick (update connection counts, push speed samples)
        self.bandwidth_tracker.finish_tick(&self.connections);

        // Alert engine checks
        self.alert_engine.check_new_apps(&self.connections, &self.dns_cache);
        self.alert_engine.check_rdp(&self.connections);
        self.alert_engine.check_bandwidth_spike(self.current_down_speed, self.current_up_speed);

        // Anomaly detection on per-app bandwidth
        self.alert_engine.check_anomalies(&self.bandwidth_tracker.apps);

        // Threat detection
        let threats = self.threat_detector.scan(&self.connections);
        if !threats.is_empty() {
            self.alert_engine.check_suspicious(&self.connections, &threats);
        }

        // DNS server change detection (every 10 ticks)
        if self.dns_tick % 10 == 0 {
            let dns_servers = crate::network::alerts::get_dns_servers();
            self.alert_engine.check_dns_servers(&dns_servers);
        }

        // Network scanner tick (auto-scans periodically)
        self.network_scanner.tick();
        if let Some(prev_devices) = self.network_scanner.poll_results() {
            self.alert_engine.check_arp_anomalies(&self.network_scanner.devices);
            self.alert_engine.check_device_changes(&self.network_scanner.devices, &prev_devices);
        }

        // System monitor tick (hosts file, proxy, WiFi, app hash changes)
        let sys_events = self.system_monitor.tick();
        if !sys_events.is_empty() {
            self.alert_engine.check_system_events(&sys_events);
        }

        // Firewall manager tick (periodic rule refresh)
        self.firewall_manager.tick();

        // Ask-to-connect mode: check new processes
        if self.firewall_manager.mode == FirewallMode::AskToConnect {
            for conn in &self.connections {
                if !conn.process_name.is_empty() && !conn.process_name.starts_with("PID:") {
                    self.firewall_manager.check_pending(&conn.process_name);
                }
            }
        }

        // Usage tracking with per-app data
        let per_app: std::collections::HashMap<String, (u64, u64)> = self.bandwidth_tracker.apps.iter()
            .map(|(k, v)| (k.clone(), (v.download_bytes, v.upload_bytes)))
            .collect();
        self.usage_tracker.update(self.total_down, self.total_up, &per_app);

        // Data plan overage alert
        let (used, limit, _pct) = self.usage_tracker.plan_status();
        let alert_pct = self.usage_tracker.data_plan().alert_pct;
        self.alert_engine.check_data_plan(used, limit, alert_pct);

        // Idle tracker tick (While You Were Away)
        let delta_down = recv.saturating_sub(self.prev_bytes_recv);
        let delta_up = sent.saturating_sub(self.prev_bytes_sent);
        let new_conn_count = self.traffic_tracker.log.iter()
            .rev()
            .take_while(|e| matches!(e.event, TrafficEventKind::NewConnection))
            .count();
        self.alert_engine.idle_tracker.tick(new_conn_count, delta_down, delta_up);

        self.tick_count = self.tick_count.wrapping_add(1);
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

    /// Returns (app_name, is_blocked, conn_count) sorted for the Firewall app list.
    /// Blocked apps first, then by connection count descending, then alphabetically.
    pub fn firewall_app_list_filtered(&self) -> Vec<(String, bool, usize)> {
        use std::collections::HashMap;
        // Count connections per process name (preserving original casing)
        let mut map: HashMap<String, (String, usize)> = HashMap::new();
        for conn in &self.connections {
            if conn.process_name.is_empty() || conn.process_name.starts_with("PID:") {
                continue;
            }
            let key = conn.process_name.to_lowercase();
            let entry = map.entry(key).or_insert((conn.process_name.clone(), 0));
            entry.1 += 1;
        }
        // Include apps that were blocked but aren't currently connecting
        for blocked in &self.firewall_manager.blocked_apps {
            map.entry(blocked.clone()).or_insert((blocked.clone(), 0));
        }
        // Apply filter
        let ft = self.firewall_manager.filter_text.to_lowercase();
        let mut list: Vec<(String, bool, usize)> = map.into_values()
            .filter(|(name, _)| ft.is_empty() || name.to_lowercase().contains(&ft))
            .map(|(name, count)| {
                let blocked = self.firewall_manager.is_psnet_blocked(&name);
                (name, blocked, count)
            })
            .collect();
        list.sort_by(|a, b| {
            b.1.cmp(&a.1)           // blocked first
                .then(b.2.cmp(&a.2)) // then most connections
                .then(a.0.cmp(&b.0)) // then alphabetical
        });
        list
    }

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
        // Notify idle tracker of user input
        self.alert_engine.idle_tracker.on_input();

        // If detail popup is open, Esc/Enter/q closes it; other keys are swallowed
        if self.detail_popup.is_some() {
            match code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    self.detail_popup = None;
                }
                _ => {}
            }
            return false;
        }

        match code {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                if !self.incognito {
                    self.alert_engine.save_alerts();
                    self.usage_tracker.save();
                }
                return true;
            }
            KeyCode::Tab => {
                self.bottom_tab = self.bottom_tab.next();
            }
            KeyCode::BackTab => {
                self.bottom_tab = self.bottom_tab.prev();
            }
            KeyCode::Char('i') | KeyCode::Char('I') => {
                self.incognito = !self.incognito;
            }
            KeyCode::Enter => {
                self.open_detail_popup();
            }
            KeyCode::Up => self.scroll_up(1),
            KeyCode::Down => self.scroll_down(1),
            KeyCode::PageUp => self.scroll_up(20),
            KeyCode::PageDown => self.scroll_down(20),
            KeyCode::Home => self.scroll_home(),
            KeyCode::End => self.scroll_end(),
            _ => {
                match self.bottom_tab {
                    BottomTab::Dashboard => self.handle_dashboard_key(code),
                    BottomTab::Connections => self.handle_connections_key(code),
                    BottomTab::Traffic => self.handle_traffic_key(code),
                    BottomTab::Alerts => self.handle_alerts_key(code),
                    BottomTab::Usage => self.handle_usage_key(code),
                    BottomTab::Firewall => self.handle_firewall_key(code),
                    BottomTab::Devices => self.handle_devices_key(code),
                }
            }
        }
        false
    }

    /// Open the detail popup for the currently selected item in the active tab.
    fn open_detail_popup(&mut self) {
        self.detail_popup = match self.bottom_tab {
            BottomTab::Connections => {
                let filtered = self.filtered_connections();
                let total = filtered.len();
                if total == 0 { return; }
                let selected = self.conn_scroll.min(total - 1);
                filtered.get(selected).map(|c| DetailKind::Connection((*c).clone()))
            }
            BottomTab::Traffic => {
                let tracker = &self.traffic_tracker;
                let filtered: Vec<_> = tracker.filtered_log();
                let filtered: Vec<_> = if tracker.hide_localhost {
                    filtered.into_iter().filter(|e| {
                        !e.local_addr.is_loopback()
                            && !e.remote_addr.map(|a| a.is_loopback()).unwrap_or(false)
                    }).collect()
                } else {
                    filtered
                };
                let total = filtered.len();
                if total == 0 { return; }
                // scroll_offset 0 = newest entry (end of vec when reversed)
                let idx = if tracker.auto_scroll || tracker.scroll_offset == 0 {
                    total.saturating_sub(1)
                } else {
                    total.saturating_sub(1).saturating_sub(tracker.scroll_offset)
                };
                filtered.get(idx).map(|e| DetailKind::TrafficEvent((*e).clone()))
            }
            BottomTab::Alerts => {
                let alerts = &self.alert_engine.alerts;
                let total = alerts.len();
                if total == 0 { return; }
                let selected = self.alert_engine.scroll_offset.min(total - 1);
                // alerts displayed newest-first (reversed), so idx = total - 1 - selected
                let idx = (total - 1).saturating_sub(selected);
                alerts.get(idx).map(|a| DetailKind::Alert(a.clone()))
            }
            BottomTab::Usage => {
                let apps = self.bandwidth_tracker.sorted_apps();
                let total = apps.len();
                if total == 0 { return; }
                let selected = self.usage_scroll.min(total - 1);
                apps.get(selected).map(|a| DetailKind::AppBandwidth((*a).clone()))
            }
            BottomTab::Devices => {
                let devices = &self.network_scanner.devices;
                let total = devices.len();
                if total == 0 { return; }
                let selected = self.device_scroll.min(total - 1);
                devices.get(selected).map(|d| DetailKind::Device(d.clone()))
            }
            BottomTab::Firewall => {
                // Enter toggles block/unblock for the selected app — no detail popup
                let apps = self.firewall_app_list_filtered();
                if apps.is_empty() { return; }
                let selected = self.firewall_manager.scroll_offset.min(apps.len() - 1);
                if let Some((name, _, _)) = apps.get(selected) {
                    let name = name.clone();
                    let path = self.connections.iter()
                        .find(|c| c.process_name.to_lowercase() == name.to_lowercase())
                        .and_then(|c| crate::network::connections::get_process_full_path(c.pid));
                    self.firewall_manager.toggle_block(&name, path.as_deref());
                }
                return;
            }
            BottomTab::Dashboard => None,
        };
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
            // Block selected connection's process via firewall
            KeyCode::Char('b') | KeyCode::Char('B') => {
                let filtered = self.filtered_connections();
                if let Some(conn) = filtered.get(self.conn_scroll) {
                    if !conn.process_name.is_empty() && !conn.process_name.starts_with("PID:") {
                        let pid = conn.pid;
                        // Use the full executable path so Windows Firewall actually matches the rule.
                        // Falling back to the exe name if the path can't be resolved.
                        let path = crate::network::connections::get_process_full_path(pid)
                            .unwrap_or_else(|| conn.process_name.clone());
                        self.firewall_manager.block_app(&path);
                    }
                }
            }
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

    fn handle_alerts_key(&mut self, code: KeyCode) {
        // Dismiss idle summary on any key press
        if self.alert_engine.idle_tracker.pending_summary.is_some() {
            self.alert_engine.idle_tracker.pending_summary = None;
            return;
        }
        match code {
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.alert_engine.mark_all_read();
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                self.alert_engine.alerts.clear();
                self.alert_engine.unread_count = 0;
            }
            // Snooze alerts for 5 minutes
            KeyCode::Char('z') | KeyCode::Char('Z') => {
                if self.alert_engine.is_snoozed() {
                    self.alert_engine.unsnooze();
                } else {
                    self.alert_engine.snooze(300); // 5 minutes
                }
            }
            _ => {}
        }
    }

    fn handle_usage_key(&mut self, code: KeyCode) {
        match code {
            // Sort keys for bandwidth table
            KeyCode::Char('1') => {
                self.bandwidth_tracker.sort_column = 0; // Total
                self.bandwidth_tracker.sort_ascending = !self.bandwidth_tracker.sort_ascending;
            }
            KeyCode::Char('2') => {
                self.bandwidth_tracker.sort_column = 1; // Download
                self.bandwidth_tracker.sort_ascending = !self.bandwidth_tracker.sort_ascending;
            }
            KeyCode::Char('3') => {
                self.bandwidth_tracker.sort_column = 2; // Upload
                self.bandwidth_tracker.sort_ascending = !self.bandwidth_tracker.sort_ascending;
            }
            KeyCode::Char('4') => {
                self.bandwidth_tracker.sort_column = 4; // Name
                self.bandwidth_tracker.sort_ascending = !self.bandwidth_tracker.sort_ascending;
            }
            // Export CSV
            KeyCode::Char('e') | KeyCode::Char('E') => {
                if let Some(data_dir) = dirs::data_dir() {
                    let path = data_dir.join("psnet").join("usage_export.csv");
                    let _ = self.usage_tracker.export_csv(&path.to_string_lossy());
                }
            }
            _ => {}
        }
    }

    fn handle_firewall_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('r') | KeyCode::Char('R') => {
                self.firewall_manager.refresh_rules();
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                self.firewall_manager.toggle_ask_to_connect();
            }
            KeyCode::Backspace => { self.firewall_manager.filter_text.pop(); }
            KeyCode::Esc => { self.firewall_manager.filter_text.clear(); }
            KeyCode::Char(c) => {
                self.firewall_manager.filter_text.push(c);
            }
            _ => {}
        }
    }

    fn handle_devices_key(&mut self, code: KeyCode) {
        // Rename mode intercepts all input
        if let Some(idx) = self.renaming_device {
            match code {
                KeyCode::Enter => {
                    let text = self.device_rename_text.trim().to_string();
                    let mac = self.network_scanner.devices.get(idx).map(|d| d.mac.clone());
                    if let Some(mac) = mac {
                        self.network_scanner.set_label(&mac, text);
                    }
                    self.renaming_device = None;
                    self.device_rename_text.clear();
                }
                KeyCode::Esc => {
                    self.renaming_device = None;
                    self.device_rename_text.clear();
                }
                KeyCode::Backspace => { self.device_rename_text.pop(); }
                KeyCode::Char(c) => { self.device_rename_text.push(c); }
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.network_scanner.start_scan();
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                let total = self.network_scanner.devices.len();
                if total > 0 {
                    let idx = self.device_scroll.min(total - 1);
                    let current = self.network_scanner.devices.get(idx)
                        .map(|d| {
                            d.custom_name.as_deref()
                                .or(d.hostname.as_deref())
                                .unwrap_or("")
                                .to_string()
                        })
                        .unwrap_or_default();
                    self.device_rename_text = current;
                    self.renaming_device = Some(idx);
                }
            }
            _ => {}
        }
    }

    fn handle_dashboard_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('1') => self.dashboard_time_range = DashboardTimeRange::Minutes5,
            KeyCode::Char('2') => self.dashboard_time_range = DashboardTimeRange::Minutes15,
            KeyCode::Char('3') => self.dashboard_time_range = DashboardTimeRange::Hour1,
            KeyCode::Char('4') => self.dashboard_time_range = DashboardTimeRange::Hours24,
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
                self.traffic_tracker.scroll_offset += n;
            }
            BottomTab::Alerts => {
                self.alert_engine.scroll_offset += n;
            }
            BottomTab::Usage => {
                self.usage_scroll = self.usage_scroll.saturating_sub(n);
            }
            BottomTab::Firewall => {
                self.firewall_manager.scroll_offset = self.firewall_manager.scroll_offset.saturating_sub(n);
            }
            BottomTab::Devices => {
                self.device_scroll = self.device_scroll.saturating_sub(n);
            }
            _ => {}
        }
    }

    fn scroll_down(&mut self, n: usize) {
        match self.bottom_tab {
            BottomTab::Connections => {
                self.conn_scroll += n;
            }
            BottomTab::Traffic => {
                self.traffic_tracker.scroll_offset =
                    self.traffic_tracker.scroll_offset.saturating_sub(n);
                if self.traffic_tracker.scroll_offset == 0 {
                    self.traffic_tracker.auto_scroll = true;
                }
            }
            BottomTab::Alerts => {
                self.alert_engine.scroll_offset = self.alert_engine.scroll_offset.saturating_sub(n);
            }
            BottomTab::Usage => {
                self.usage_scroll += n;
            }
            BottomTab::Firewall => {
                self.firewall_manager.scroll_offset += n;
            }
            BottomTab::Devices => {
                self.device_scroll += n;
            }
            _ => {}
        }
    }

    fn scroll_home(&mut self) {
        match self.bottom_tab {
            BottomTab::Connections => self.conn_scroll = 0,
            BottomTab::Traffic => {
                self.traffic_tracker.auto_scroll = false;
                self.traffic_tracker.scroll_offset = self.traffic_tracker.log.len();
            }
            BottomTab::Alerts => {
                // Go to oldest alert
                self.alert_engine.scroll_offset = self.alert_engine.alerts.len();
            }
            BottomTab::Firewall => {
                self.firewall_manager.scroll_offset = 0;
            }
            BottomTab::Devices => {
                self.device_scroll = 0;
            }
            _ => {}
        }
    }

    fn scroll_end(&mut self) {
        match self.bottom_tab {
            BottomTab::Connections => self.conn_scroll = self.connections.len(),
            BottomTab::Traffic => {
                self.traffic_tracker.auto_scroll = true;
                self.traffic_tracker.scroll_offset = 0;
            }
            BottomTab::Alerts => {
                // Go to newest alert
                self.alert_engine.scroll_offset = 0;
            }
            BottomTab::Firewall => {
                self.firewall_manager.scroll_offset = self.firewall_app_list_filtered().len();
            }
            BottomTab::Devices => {
                self.device_scroll = self.network_scanner.devices.len();
            }
            _ => {}
        }
    }
}
