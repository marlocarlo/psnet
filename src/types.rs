use std::collections::HashMap;
use std::net::IpAddr;

use chrono::NaiveTime;

// ─── DNS cache ───────────────────────────────────────────────────────────────

pub type DnsCache = HashMap<IpAddr, Option<String>>;

// ─── Protocol ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ConnProto {
    Tcp,
    Udp,
}

impl ConnProto {
    pub fn label(&self) -> &str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

// ─── TCP State ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown(u32),
}

impl TcpState {
    pub fn from_raw(v: u32) -> Self {
        match v {
            1 => Self::Closed,
            2 => Self::Listen,
            3 => Self::SynSent,
            4 => Self::SynReceived,
            5 => Self::Established,
            6 => Self::FinWait1,
            7 => Self::FinWait2,
            8 => Self::CloseWait,
            9 => Self::Closing,
            10 => Self::LastAck,
            11 => Self::TimeWait,
            12 => Self::DeleteTcb,
            _ => Self::Unknown(v),
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Self::Closed => "CLOSED",
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECV",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT1",
            Self::FinWait2 => "FIN_WAIT2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::DeleteTcb => "DELETE_TCB",
            Self::Unknown(_) => "UNKNOWN",
        }
    }

    pub fn color(&self) -> ratatui::style::Color {
        use ratatui::style::Color;
        match self {
            Self::Established => Color::Green,
            Self::Listen => Color::Cyan,
            Self::SynSent | Self::SynReceived => Color::Yellow,
            Self::TimeWait | Self::FinWait1 | Self::FinWait2 => Color::Magenta,
            Self::CloseWait | Self::Closing | Self::LastAck => Color::LightRed,
            Self::Closed | Self::DeleteTcb => Color::DarkGray,
            Self::Unknown(_) => Color::Gray,
        }
    }
}

// ─── Connection ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Connection {
    pub proto: ConnProto,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub state: Option<TcpState>,
    pub pid: u32,
    pub process_name: String,
    /// DNS-resolved hostname for remote address (if available).
    pub dns_hostname: Option<String>,
}

/// Unique key for identifying a connection across ticks.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConnKey {
    pub proto: ConnProto,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
}

impl Connection {
    pub fn key(&self) -> ConnKey {
        ConnKey {
            proto: self.proto.clone(),
            local_addr: self.local_addr,
            local_port: self.local_port,
            remote_addr: self.remote_addr,
            remote_port: self.remote_port,
        }
    }

    /// Heuristic: is this an outbound connection?
    pub fn is_outbound(&self) -> bool {
        if let Some(rp) = self.remote_port {
            // Well-known remote ports suggest we initiated the connection
            matches!(rp, 80 | 443 | 22 | 21 | 25 | 53 | 110 | 143 | 993 | 995
                | 587 | 465 | 8080 | 8443 | 3306 | 5432 | 6379 | 27017)
                || (self.local_port > 1024 && rp <= 1024)
                || (self.local_port > 49152)
        } else {
            false
        }
    }
}

// ─── Speed history ───────────────────────────────────────────────────────────

pub struct SpeedHistory {
    pub download: std::collections::VecDeque<f64>,
    pub upload: std::collections::VecDeque<f64>,
    pub max_points: usize,
}

impl SpeedHistory {
    pub fn new(max_points: usize) -> Self {
        Self {
            download: std::collections::VecDeque::from(vec![0.0; max_points]),
            upload: std::collections::VecDeque::from(vec![0.0; max_points]),
            max_points,
        }
    }

    pub fn push(&mut self, down: f64, up: f64) {
        self.download.push_back(down);
        self.upload.push_back(up);
        if self.download.len() > self.max_points {
            self.download.pop_front();
        }
        if self.upload.len() > self.max_points {
            self.upload.pop_front();
        }
    }
}

// ─── Traffic event (for live capture tab) ────────────────────────────────────

#[derive(Clone, Debug)]
pub enum TrafficEventKind {
    NewConnection,
    ConnectionClosed,
    StateChange { from: TcpState, to: TcpState },
    DataActivity { bytes: usize, inbound: bool },
}

impl TrafficEventKind {
    pub fn label(&self) -> &str {
        match self {
            Self::NewConnection => "CONNECT",
            Self::ConnectionClosed => "CLOSE",
            Self::StateChange { .. } => "STATE",
            Self::DataActivity { .. } => "DATA",
        }
    }

    pub fn color(&self) -> ratatui::style::Color {
        use ratatui::style::Color;
        match self {
            Self::NewConnection => Color::Green,
            Self::ConnectionClosed => Color::Red,
            Self::StateChange { .. } => Color::Yellow,
            Self::DataActivity { inbound: true, .. } => Color::Cyan,
            Self::DataActivity { inbound: false, .. } => Color::Magenta,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TrafficEntry {
    pub timestamp: NaiveTime,
    pub event: TrafficEventKind,
    pub proto: ConnProto,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub remote_addr: Option<IpAddr>,
    pub remote_port: Option<u16>,
    pub process_name: String,
    pub outbound: bool,
    pub state_label: String,
    /// DNS-resolved hostname for remote address (if available).
    pub dns_name: Option<String>,
    /// Estimated data transferred (bytes) for this connection at event time.
    #[allow(dead_code)]
    pub data_size: Option<u64>,
}

// ─── Bottom pane tab ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BottomTab {
    Traffic,
    Connections,
}

impl BottomTab {
    pub fn next(&self) -> Self {
        match self {
            Self::Traffic => Self::Connections,
            Self::Connections => Self::Traffic,
        }
    }
}

// ─── Process name cache ──────────────────────────────────────────────────────

pub type PidCache = HashMap<u32, String>;

// ─── Packet snippet (for live wire preview) ──────────────────────────────────

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct PacketSnippet {
    pub timestamp: NaiveTime,
    pub direction: PacketDirection,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: ConnProto,
    /// Printable ASCII snippet from the payload
    pub snippet: String,
    /// Total payload size in bytes
    pub payload_size: usize,
}

#[derive(Clone, Debug, PartialEq)]
pub enum PacketDirection {
    Inbound,
    Outbound,
}
