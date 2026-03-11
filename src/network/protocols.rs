use std::collections::HashMap;
use ratatui::style::Color;

/// Known network protocols detected via port heuristics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Dhcp,
    Dns,
    Http,
    Https,
    Ssh,
    Ftp,
    Smtp,
    Imap,
    Pop3,
    Rdp,
    Smb,
    Ntp,
    Snmp,
    Mdns,
    Llmnr,
    Ssdp,
    Quic,
    Other,
}

impl Protocol {
    /// Short display label for the tag cloud.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Dhcp => "DHCP",
            Self::Dns => "DNS",
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Ssh => "SSH",
            Self::Ftp => "FTP",
            Self::Smtp => "SMTP",
            Self::Imap => "IMAP",
            Self::Pop3 => "POP3",
            Self::Rdp => "RDP",
            Self::Smb => "SMB",
            Self::Ntp => "NTP",
            Self::Snmp => "SNMP",
            Self::Mdns => "mDNS",
            Self::Llmnr => "LLMNR",
            Self::Ssdp => "SSDP",
            Self::Quic => "QUIC",
            Self::Other => "OTHER",
        }
    }

    /// Distinct color per protocol for the tag cloud.
    pub fn color(&self) -> Color {
        match self {
            Self::Dhcp => Color::Rgb(180, 140, 255),
            Self::Dns => Color::Rgb(80, 200, 255),
            Self::Http => Color::Rgb(100, 220, 100),
            Self::Https => Color::Rgb(60, 180, 60),
            Self::Ssh => Color::Rgb(255, 160, 60),
            Self::Ftp => Color::Rgb(200, 100, 255),
            Self::Smtp => Color::Rgb(255, 120, 120),
            Self::Imap => Color::Rgb(255, 140, 180),
            Self::Pop3 => Color::Rgb(220, 100, 160),
            Self::Rdp => Color::Rgb(255, 80, 80),
            Self::Smb => Color::Rgb(200, 180, 100),
            Self::Ntp => Color::Rgb(100, 200, 200),
            Self::Snmp => Color::Rgb(160, 200, 100),
            Self::Mdns => Color::Rgb(120, 180, 255),
            Self::Llmnr => Color::Rgb(140, 160, 255),
            Self::Ssdp => Color::Rgb(200, 160, 200),
            Self::Quic => Color::Rgb(0, 220, 180),
            Self::Other => Color::Rgb(140, 140, 140),
        }
    }

    /// Detect protocol from source/destination ports and transport type.
    pub fn from_ports(src: u16, dst: u16, is_udp: bool) -> Self {
        if let Some(p) = Self::match_port(dst, is_udp) {
            return p;
        }
        if let Some(p) = Self::match_port(src, is_udp) {
            return p;
        }
        Self::Other
    }

    fn match_port(port: u16, is_udp: bool) -> Option<Self> {
        match port {
            53 => Some(Self::Dns),
            80 | 8080 => Some(Self::Http),
            443 => {
                if is_udp { Some(Self::Quic) } else { Some(Self::Https) }
            }
            22 => Some(Self::Ssh),
            21 | 20 => Some(Self::Ftp),
            25 | 587 | 465 => Some(Self::Smtp),
            143 | 993 => Some(Self::Imap),
            110 | 995 => Some(Self::Pop3),
            3389 => Some(Self::Rdp),
            445 | 139 => Some(Self::Smb),
            123 => Some(Self::Ntp),
            161 | 162 => Some(Self::Snmp),
            5353 => Some(Self::Mdns),
            5355 => Some(Self::Llmnr),
            1900 => Some(Self::Ssdp),
            67 | 68 => Some(Self::Dhcp),
            _ => None,
        }
    }
}

/// Activity record for a single protocol.
pub struct ProtocolActivity {
    /// Total packets ever seen for this protocol.
    pub count: u64,
    /// Tick when this protocol was last seen.
    pub last_tick: u64,
    /// Packets seen in the recent window (last fade_ticks ticks).
    pub recent_count: u64,
    /// Per-tick counts for computing recent_count (ring of last fade_ticks).
    tick_counts: Vec<u64>,
    /// Index into tick_counts ring buffer.
    tick_ring_idx: usize,
    /// Last tick when tick_counts was advanced.
    last_ring_tick: u64,
}

impl ProtocolActivity {
    fn new(fade_ticks: u64) -> Self {
        Self {
            count: 0,
            last_tick: 0,
            recent_count: 0,
            tick_counts: vec![0; fade_ticks as usize],
            tick_ring_idx: 0,
            last_ring_tick: 0,
        }
    }

    /// Advance the ring buffer to the current tick, zeroing skipped slots.
    fn advance_to(&mut self, tick: u64) {
        if self.last_ring_tick == 0 && self.count == 0 {
            self.last_ring_tick = tick;
            return;
        }
        let steps = tick.saturating_sub(self.last_ring_tick);
        if steps == 0 {
            return;
        }
        let len = self.tick_counts.len();
        let steps = steps.min(len as u64) as usize;
        for _ in 0..steps {
            self.tick_ring_idx = (self.tick_ring_idx + 1) % len;
            self.recent_count = self.recent_count.saturating_sub(self.tick_counts[self.tick_ring_idx]);
            self.tick_counts[self.tick_ring_idx] = 0;
        }
        self.last_ring_tick = tick;
    }

    fn record(&mut self, tick: u64) {
        self.advance_to(tick);
        self.count += 1;
        self.last_tick = tick;
        self.tick_counts[self.tick_ring_idx] += 1;
        self.recent_count += 1;
    }
}

/// Tracks which network protocols are active and their packet counts.
pub struct ProtocolTracker {
    pub activity: HashMap<Protocol, ProtocolActivity>,
    /// How many ticks before a protocol "fades" (stops being highlighted).
    pub fade_ticks: u64,
}

impl ProtocolTracker {
    pub fn new() -> Self {
        Self {
            activity: HashMap::new(),
            fade_ticks: 10,
        }
    }

    /// Record a packet with the given ports.
    pub fn record(&mut self, src_port: u16, dst_port: u16, is_udp: bool, tick: u64) {
        let proto = Protocol::from_ports(src_port, dst_port, is_udp);
        let fade = self.fade_ticks;
        let entry = self.activity
            .entry(proto)
            .or_insert_with(|| ProtocolActivity::new(fade));
        entry.record(tick);
    }

    /// Returns protocols seen at least once, sorted by most recent activity first.
    pub fn active_protocols(&self, current_tick: u64) -> Vec<(&Protocol, &ProtocolActivity)> {
        let mut protos: Vec<_> = self.activity.iter()
            .filter(|(_, a)| a.count > 0)
            .collect();
        protos.sort_by(|(_, a), (_, b)| {
            let a_active = current_tick.saturating_sub(a.last_tick) <= self.fade_ticks;
            let b_active = current_tick.saturating_sub(b.last_tick) <= self.fade_ticks;
            match (a_active, b_active) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => b.count.cmp(&a.count),
            }
        });
        protos
    }

    /// Brightness from 1.0 (just seen) fading to 0.0 over fade_ticks.
    pub fn brightness(&self, proto: &Protocol, current_tick: u64) -> f64 {
        if let Some(activity) = self.activity.get(proto) {
            let age = current_tick.saturating_sub(activity.last_tick);
            if age >= self.fade_ticks {
                0.0
            } else {
                1.0 - (age as f64 / self.fade_ticks as f64)
            }
        } else {
            0.0
        }
    }
}
