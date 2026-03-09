//! Detail popup overlay — shown when user presses Enter on any selected row.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::network::dns::port_service_name;
use crate::types::{AlertKind, DetailKind, FirewallAction};
use crate::utils::{format_bytes, format_speed};

/// Render the detail popup overlay if one is active.
pub fn draw_detail_popup(f: &mut Frame, app: &App) {
    let Some(ref detail) = app.detail_popup else { return };

    let area = centered_rect(70, 60, f.area());
    f.render_widget(Clear, area);

    match detail {
        DetailKind::Connection(conn) => draw_connection_detail(f, area, conn, app),
        DetailKind::TrafficEvent(entry) => draw_traffic_detail(f, area, entry, app),
        DetailKind::Alert(alert) => draw_alert_detail(f, area, alert),
        DetailKind::AppBandwidth(bw) => draw_bandwidth_detail(f, area, bw),
        DetailKind::Device(device) => draw_device_detail(f, area, device, app),
        DetailKind::FirewallRule(rule) => draw_firewall_detail(f, area, rule),
    }
}

// ─── Connection detail ───────────────────────────────────────────────────────

fn draw_connection_detail(f: &mut Frame, area: Rect, conn: &crate::types::Connection, app: &App) {
    let geo = conn.remote_addr
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .and_then(|ip| app.geoip.lookup(ip));

    let port = conn.remote_port.unwrap_or(conn.local_port);
    let service = port_service_name(port)
        .map(|s| format!("{} (port {})", s, port))
        .unwrap_or_else(|| format!("port {}", port));

    let remote_host = conn.dns_hostname.clone()
        .or_else(|| conn.remote_addr.map(|ip| ip.to_string()))
        .unwrap_or_else(|| "*".to_string());

    let state_str = conn.state.as_ref().map(|s| s.label().to_string()).unwrap_or_else(|| "—".to_string());
    let state_color = conn.state.as_ref().map(|s| s.color()).unwrap_or(Color::Gray);
    let country_str = geo.map(|g| format!("{} {} ({})", g.flag, g.name, g.code)).unwrap_or_else(|| "Local / Private".to_string());
    let remote_addr_str = conn.remote_addr
        .map(|ip| format!("{}:{}", ip, conn.remote_port.unwrap_or(0)))
        .unwrap_or_else(|| "—".to_string());

    let mut lines = header_lines(" Connection Detail ");
    lines.push(row("Protocol",    conn.proto.label().to_string(),                   Color::Rgb(100, 220, 255)));
    lines.push(row("Process",     conn.process_name.clone(),                        Color::Rgb(130, 200, 140)));
    lines.push(row("PID",         conn.pid.to_string(),                             Color::Rgb(120, 130, 160)));
    lines.push(row("Direction",   if conn.is_outbound() { "Outbound →" } else { "Inbound ←" }.to_string(), Color::Rgb(200, 180, 100)));
    lines.push(row("Local",       format!("{}:{}", conn.local_addr, conn.local_port), Color::Rgb(150, 160, 190)));
    lines.push(row("Remote",      remote_addr_str,                                  Color::Rgb(170, 185, 210)));
    lines.push(row("DNS Name",    remote_host,                                      Color::Rgb(100, 220, 255)));
    lines.push(row("Service",     service,                                          Color::Rgb(200, 180, 80)));
    lines.push(row("State",       state_str,                                        state_color));
    lines.push(row("Country",     country_str,                                      Color::Rgb(170, 200, 230)));
    lines.push(Line::from(""));
    lines.push(dismiss_line());

    render_popup(f, area, lines);
}

// ─── Traffic event detail ────────────────────────────────────────────────────

fn draw_traffic_detail(f: &mut Frame, area: Rect, entry: &crate::types::TrafficEntry, app: &App) {
    let geo = entry.remote_addr
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .and_then(|ip| app.geoip.lookup(ip));

    let country_str = geo.map(|g| format!("{} {} ({})", g.flag, g.name, g.code)).unwrap_or_else(|| "Local / Private".to_string());

    let event_str = match &entry.event {
        crate::types::TrafficEventKind::NewConnection => "● New Connection".to_string(),
        crate::types::TrafficEventKind::ConnectionClosed => "✕ Connection Closed".to_string(),
        crate::types::TrafficEventKind::StateChange { from, to } => format!("↔ {} → {}", from.label(), to.label()),
        crate::types::TrafficEventKind::DataActivity { bytes, inbound } => {
            format!("{} Data: {}", if *inbound { "◀ Inbound" } else { "▶ Outbound" }, format_bytes(*bytes as u64))
        }
    };
    let event_color = entry.event.color();

    let remote_str = match (entry.remote_addr, entry.remote_port) {
        (Some(a), Some(p)) => format!("{}:{}", a, p),
        (Some(a), None) => a.to_string(),
        _ => "—".to_string(),
    };
    let port = entry.remote_port.unwrap_or(entry.local_port);
    let service = port_service_name(port)
        .map(|s| format!("{}/{}", s, entry.proto.label()))
        .unwrap_or_else(|| format!("{}/{}", port, entry.proto.label()));
    let data_str = entry.data_size.map(|b| format_bytes(b)).unwrap_or_else(|| "—".to_string());

    let mut lines = header_lines(" Traffic Event Detail ");
    lines.push(row("Time",       entry.timestamp.format("%H:%M:%S").to_string(), Color::Rgb(120, 130, 160)));
    lines.push(row("Event",      event_str,                                      event_color));
    lines.push(row("Process",    entry.process_name.clone(),                     Color::Rgb(130, 200, 140)));
    lines.push(row("Protocol",   entry.proto.label().to_string(),                Color::Rgb(100, 220, 255)));
    lines.push(row("Direction",  if entry.outbound { "Outbound →" } else { "Inbound ←" }.to_string(), Color::Rgb(200, 180, 100)));
    lines.push(row("Local",      format!("{}:{}", entry.local_addr, entry.local_port), Color::Rgb(150, 160, 190)));
    lines.push(row("Remote",     remote_str,                                     Color::Rgb(170, 185, 210)));
    lines.push(row("DNS Name",   entry.dns_name.clone().unwrap_or_else(|| "—".to_string()), Color::Rgb(100, 220, 255)));
    lines.push(row("Service",    service,                                        Color::Rgb(200, 180, 80)));
    lines.push(row("State",      entry.state_label.clone(),                      Color::Rgb(160, 180, 140)));
    lines.push(row("Country",    country_str,                                    Color::Rgb(170, 200, 230)));
    lines.push(row("Data",       data_str,                                       Color::Rgb(130, 160, 200)));
    lines.push(Line::from(""));
    lines.push(dismiss_line());

    render_popup(f, area, lines);
}

// ─── Alert detail ────────────────────────────────────────────────────────────

fn draw_alert_detail(f: &mut Frame, area: Rect, alert: &crate::types::Alert) {
    let severity = alert.kind.severity();
    let sev_color = severity.color();

    let mut lines = header_lines(" Alert Detail ");
    lines.push(row("Time",     alert.timestamp.format("%H:%M:%S").to_string(), Color::Rgb(120, 130, 160)));
    lines.push(row("Severity", severity.label().to_string(),                   sev_color));
    lines.push(row("Type",     alert.kind.label().to_string(),                 Color::Rgb(180, 190, 220)));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("  {}", alert.kind.description()),
        Style::default().fg(Color::Rgb(200, 210, 230)).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    match &alert.kind {
        AlertKind::SuspiciousHost { process_name, ip, reason } => {
            lines.push(row("Process", process_name.clone(), Color::Rgb(130, 200, 140)));
            lines.push(row("IP",      ip.to_string(),       Color::Rgb(255, 120, 80)));
            lines.push(row("Reason",  reason.clone(),       Color::Rgb(255, 180, 80)));
        }
        AlertKind::NewAppFirstConnection { process_name, remote } => {
            lines.push(row("Process", process_name.clone(), Color::Rgb(130, 200, 140)));
            lines.push(row("Remote",  remote.clone(),       Color::Rgb(100, 220, 255)));
        }
        AlertKind::BandwidthSpike { direction, speed_bps, threshold_bps } => {
            lines.push(row("Direction", direction.clone(),           Color::Rgb(200, 180, 100)));
            lines.push(row("Speed",     format_speed(*speed_bps),    Color::Rgb(255, 120, 80)));
            lines.push(row("Threshold", format_speed(*threshold_bps), Color::Rgb(150, 160, 180)));
        }
        AlertKind::NewDevice { ip, mac, hostname } => {
            lines.push(row("IP",       ip.to_string(),                                   Color::Rgb(100, 220, 255)));
            lines.push(row("MAC",      mac.clone(),                                      Color::Rgb(150, 160, 180)));
            lines.push(row("Hostname", hostname.clone().unwrap_or_else(|| "unknown".to_string()), Color::Rgb(180, 190, 140)));
        }
        AlertKind::ArpAnomaly { ip, expected_mac, actual_mac } => {
            lines.push(row("IP",           ip.to_string(),        Color::Rgb(100, 220, 255)));
            lines.push(row("Expected MAC", expected_mac.clone(),  Color::Rgb(150, 160, 180)));
            lines.push(row("Actual MAC",   actual_mac.clone(),    Color::Rgb(255, 120, 80)));
        }
        AlertKind::BandwidthOverage { used_bytes, limit_bytes } => {
            lines.push(row("Used",  format_bytes(*used_bytes),  Color::Rgb(255, 120, 80)));
            lines.push(row("Limit", format_bytes(*limit_bytes), Color::Rgb(150, 160, 180)));
        }
        AlertKind::TrafficAnomaly { process_name, current_bytes, baseline_bytes } => {
            lines.push(row("Process",  process_name.clone(),        Color::Rgb(130, 200, 140)));
            lines.push(row("Current",  format_bytes(*current_bytes), Color::Rgb(255, 180, 80)));
            lines.push(row("Baseline", format_bytes(*baseline_bytes), Color::Rgb(150, 160, 180)));
        }
        _ => {}
    }

    lines.push(Line::from(""));
    lines.push(dismiss_line());
    render_popup(f, area, lines);
}

// ─── App bandwidth detail ────────────────────────────────────────────────────

fn draw_bandwidth_detail(f: &mut Frame, area: Rect, bw: &crate::types::AppBandwidth) {
    let current_down = bw.recent_down.back().copied().unwrap_or(0.0);
    let current_up = bw.recent_up.back().copied().unwrap_or(0.0);
    let peak_down = bw.recent_down.iter().copied().fold(0.0_f64, f64::max);
    let peak_up = bw.recent_up.iter().copied().fold(0.0_f64, f64::max);

    let active_str = if bw.active_connections > 0 {
        format!("{} active connections", bw.active_connections)
    } else {
        "idle".to_string()
    };
    let active_color = if bw.active_connections > 0 { Color::Rgb(80, 200, 120) } else { Color::Rgb(100, 110, 130) };

    let mut lines = header_lines(" App Bandwidth Detail ");
    lines.push(row("Application",  bw.process_name.clone(),           Color::Rgb(130, 200, 140)));
    lines.push(row("Status",       active_str,                        active_color));
    lines.push(Line::from(""));
    lines.push(row("Downloaded",   format_bytes(bw.download_bytes),  Color::Rgb(80, 180, 255)));
    lines.push(row("Uploaded",     format_bytes(bw.upload_bytes),    Color::Rgb(180, 120, 255)));
    lines.push(row("Total",        format_bytes(bw.total_bytes()),   Color::Rgb(170, 185, 210)));
    lines.push(Line::from(""));
    lines.push(row("Speed ↓",      format_speed(current_down),       Color::Rgb(80, 200, 160)));
    lines.push(row("Speed ↑",      format_speed(current_up),         Color::Rgb(200, 140, 255)));
    lines.push(row("Peak ↓",       format_speed(peak_down),          Color::Rgb(80, 180, 255)));
    lines.push(row("Peak ↑",       format_speed(peak_up),            Color::Rgb(180, 120, 255)));
    lines.push(row("Last Seen",    bw.last_seen.format("%H:%M:%S").to_string(), Color::Rgb(120, 130, 160)));
    lines.push(Line::from(""));
    lines.push(dismiss_line());
    render_popup(f, area, lines);
}

// ─── Device detail ───────────────────────────────────────────────────────────

fn draw_device_detail(f: &mut Frame, area: Rect, device: &crate::types::LanDevice, app: &App) {
    let is_gateway = app.network_scanner.gateway
        .map(|gw| device.ip == std::net::IpAddr::V4(gw))
        .unwrap_or(false);

    let status_color = if device.is_online { Color::Rgb(80, 200, 120) } else { Color::Rgb(100, 100, 120) };

    let mut lines = header_lines(" Device Detail ");
    lines.push(row("Status",     if device.is_online { "● Online" } else { "○ Offline" }.to_string(), status_color));
    lines.push(row("Role",       if is_gateway { "Gateway" } else { "Host" }.to_string(), if is_gateway { Color::Rgb(255, 200, 80) } else { Color::Rgb(150, 160, 190) }));
    lines.push(row("IP Address", device.ip.to_string(),                                   Color::Rgb(100, 180, 255)));
    lines.push(row("MAC",        device.mac.clone(),                                      Color::Rgb(150, 160, 180)));
    lines.push(row("Vendor",     device.vendor.clone().unwrap_or_else(|| "Unknown".to_string()), Color::Rgb(180, 170, 140)));
    lines.push(row("Hostname",   device.hostname.clone().unwrap_or_else(|| "—".to_string()),     Color::Rgb(130, 200, 140)));
    lines.push(row("First Seen", device.first_seen.format("%H:%M:%S").to_string(),        Color::Rgb(120, 130, 160)));
    lines.push(row("Last Seen",  device.last_seen.format("%H:%M:%S").to_string(),         Color::Rgb(120, 130, 160)));
    lines.push(Line::from(""));
    lines.push(dismiss_line());
    render_popup(f, area, lines);
}

// ─── Firewall rule detail ────────────────────────────────────────────────────

fn draw_firewall_detail(f: &mut Frame, area: Rect, rule: &crate::types::FirewallRule) {
    let action_color = match rule.action {
        FirewallAction::Allow => Color::Rgb(80, 200, 120),
        FirewallAction::Block => Color::Rgb(255, 80, 80),
    };
    let enabled_color = if rule.enabled { Color::Rgb(80, 200, 120) } else { Color::Rgb(100, 100, 120) };

    let mut lines = header_lines(" Firewall Rule Detail ");
    lines.push(row("Rule Name",  rule.name.clone(),                                            Color::Rgb(155, 170, 200)));
    lines.push(row("Program",    rule.process_name.clone().unwrap_or_else(|| "Any".to_string()), Color::Rgb(130, 200, 140)));
    lines.push(row("Action",     rule.action.label().to_string(),                              action_color));
    lines.push(row("Direction",  rule.direction.label().to_string(),                           Color::Rgb(130, 150, 190)));
    lines.push(row("Enabled",    if rule.enabled { "Yes" } else { "No" }.to_string(),          enabled_color));
    lines.push(row("Profile",    rule.profile.clone(),                                         Color::Rgb(100, 110, 130)));
    lines.push(Line::from(""));
    lines.push(dismiss_line());
    render_popup(f, area, lines);
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

fn header_lines(title: &str) -> Vec<Line<'static>> {
    vec![
        Line::from(Span::styled(
            format!("  {}", title),
            Style::default()
                .fg(Color::Rgb(200, 220, 255))
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ─────────────────────────────────────────────────────────",
            Style::default().fg(Color::Rgb(35, 50, 80)),
        )),
        Line::from(""),
    ]
}

/// A labeled row with right-hand value — all strings owned.
fn row(label: &'static str, value: String, value_color: Color) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {:<16}", label),
            Style::default().fg(Color::Rgb(90, 105, 135)),
        ),
        Span::styled(value, Style::default().fg(value_color).add_modifier(Modifier::BOLD)),
    ])
}

fn dismiss_line() -> Line<'static> {
    Line::from(Span::styled(
        "  [ Enter / Esc to close ]",
        Style::default().fg(Color::Rgb(65, 80, 110)).add_modifier(Modifier::ITALIC),
    ))
}

fn render_popup(f: &mut Frame, area: Rect, lines: Vec<Line<'static>>) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(60, 100, 180)))
        .style(Style::default().bg(Color::Rgb(10, 14, 28)));

    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(
        Paragraph::new(lines).style(Style::default().bg(Color::Rgb(10, 14, 28))),
        inner,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let pad_v = (100u16.saturating_sub(percent_y)) / 2;
    let pad_h = (100u16.saturating_sub(percent_x)) / 2;
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(pad_v),
            Constraint::Percentage(percent_y),
            Constraint::Percentage(pad_v),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(pad_h),
            Constraint::Percentage(percent_x),
            Constraint::Percentage(pad_h),
        ])
        .split(vertical[1])[1]
}
