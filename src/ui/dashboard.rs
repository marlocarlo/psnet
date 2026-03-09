//! Dashboard tab — GlassWire-style overview with traffic graph, world map,
//! top apps bar chart, and network health summary.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::types::TcpState;
use crate::utils::{format_bytes, format_speed};

use super::widgets::bar_chart::{draw_bar_chart, BarEntry};
use super::widgets::health_gauge::{compute_health_score, draw_health_gauge};
use super::widgets::traffic_chart::draw_traffic_chart;
use super::widgets::world_map::{
    draw_world_map_dots, fade_brightness, ip_to_seed, ConnectionDot,
};

/// Palette of colors for top-app bar chart entries.
const APP_COLORS: [ratatui::style::Color; 8] = [
    ratatui::style::Color::Rgb(50, 160, 255),  // cyan
    ratatui::style::Color::Rgb(180, 100, 255),  // purple
    ratatui::style::Color::Rgb(80, 200, 120),   // green
    ratatui::style::Color::Rgb(255, 200, 80),   // gold
    ratatui::style::Color::Rgb(255, 130, 60),   // orange
    ratatui::style::Color::Rgb(100, 220, 255),  // light cyan
    ratatui::style::Color::Rgb(220, 130, 200),  // pink
    ratatui::style::Color::Rgb(170, 200, 230),  // steel
];

pub fn draw_dashboard(f: &mut Frame, area: Rect, app: &App) {
    if app.map_fullscreen {
        // Full-screen map mode (toggle with 'm')
        let main_split = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Live summary strip
                Constraint::Min(10),  // Full map
                Constraint::Length(1), // Footer hint
            ])
            .split(area);

        draw_summary_strip(f, main_split[0], app);
        draw_country_map(f, main_split[1], app);

        let hint = Line::from(vec![
            Span::styled(
                " m:Exit Map  ",
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                "1-4:Time Range  ",
                Style::default().fg(Color::Rgb(60, 80, 110)),
            ),
            Span::styled(
                "Tab:Next tab",
                Style::default().fg(Color::Rgb(60, 80, 110)),
            ),
        ]);
        f.render_widget(
            Paragraph::new(hint).style(Style::default().bg(Color::Rgb(12, 16, 30))),
            main_split[2],
        );
        return;
    }

    // ── Layout: summary strip → traffic graph → bottom panels ──
    let main_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),      // Live summary strip
            Constraint::Percentage(47), // Traffic graph
            Constraint::Percentage(50), // Bottom panels
        ])
        .split(area);

    draw_summary_strip(f, main_split[0], app);

    // Remap remaining layout to sub-slices
    let traffic_area = main_split[1];
    let bottom_area = main_split[2];

    let bottom_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(55), // World map
            Constraint::Percentage(45), // Stats + bar chart
        ])
        .split(bottom_area);

    let right_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // Health gauge / summary
            Constraint::Min(5),   // Top apps bar chart
        ])
        .split(bottom_split[1]);

    // ── 1. Traffic Graph ──
    draw_traffic_graph(f, traffic_area, app);

    // ── 2. World Map ──
    draw_country_map(f, bottom_split[0], app);

    // ── 3. Health Gauge ──
    draw_health(f, right_split[0], app);

    // ── 4. Top Apps Bar Chart ──
    draw_top_apps(f, right_split[1], app);
}

// ─── Live summary strip ───────────────────────────────────────────────────────

fn draw_summary_strip(f: &mut Frame, area: Rect, app: &App) {
    let active = app.connections.iter()
        .filter(|c| matches!(c.state.as_ref(), Some(TcpState::Established)))
        .count();
    let total_conns = app.connections.len();
    let unread_alerts = app.alert_engine.unread();
    let total_alerts = app.alert_engine.alerts.len();
    let threats = app.alert_engine.alerts.iter()
        .filter(|a| matches!(a.kind, crate::types::AlertKind::SuspiciousHost { .. }))
        .count();
    let (today_down, today_up) = app.usage_tracker.today_usage();
    let fw_status = if app.firewall_manager.enabled { "ON" } else { "OFF" };
    let fw_color = if app.firewall_manager.enabled { Color::Rgb(80, 200, 120) } else { Color::Rgb(255, 80, 80) };

    // Pulsing live dot using tick_count
    let live_dot = if app.tick_count % 2 == 0 { "●" } else { "○" };
    let live_color = if app.current_down_speed > 5_000.0 || app.current_up_speed > 5_000.0 {
        Color::Rgb(80, 220, 120)
    } else {
        Color::Rgb(60, 80, 100)
    };

    let sep = || Span::styled("  │  ", Style::default().fg(Color::Rgb(35, 48, 72)));

    let line = Line::from(vec![
        Span::styled(format!(" {} LIVE  ", live_dot), Style::default().fg(live_color).add_modifier(Modifier::BOLD)),
        Span::styled("▼ ", Style::default().fg(Color::Rgb(80, 180, 255))),
        Span::styled(format_speed(app.current_down_speed), Style::default().fg(Color::Rgb(100, 200, 255)).add_modifier(Modifier::BOLD)),
        Span::styled("  ▲ ", Style::default().fg(Color::Rgb(180, 120, 255))),
        Span::styled(format_speed(app.current_up_speed), Style::default().fg(Color::Rgb(200, 140, 255)).add_modifier(Modifier::BOLD)),
        sep(),
        Span::styled(format!("{}", active), Style::default().fg(Color::Rgb(80, 220, 120)).add_modifier(Modifier::BOLD)),
        Span::styled(format!(" active / {} conns", total_conns), Style::default().fg(Color::Rgb(90, 110, 140))),
        sep(),
        Span::styled("Today ▼", Style::default().fg(Color::Rgb(80, 150, 200))),
        Span::styled(format!(" {} ", format_bytes(today_down)), Style::default().fg(Color::Rgb(130, 170, 220))),
        Span::styled("▲", Style::default().fg(Color::Rgb(160, 100, 200))),
        Span::styled(format!(" {}", format_bytes(today_up)), Style::default().fg(Color::Rgb(180, 140, 230))),
        sep(),
        Span::styled(
            if unread_alerts > 0 { format!("⚠ {} alerts ({} new)", total_alerts, unread_alerts) }
            else { format!("✓ {} alerts", total_alerts) },
            Style::default().fg(if unread_alerts > 0 { Color::Rgb(255, 200, 60) } else { Color::Rgb(70, 90, 120) })
                .add_modifier(if unread_alerts > 0 { Modifier::BOLD } else { Modifier::empty() }),
        ),
        sep(),
        Span::styled(
            if threats > 0 { format!("⚡ {} threats", threats) } else { "✓ No threats".to_string() },
            Style::default().fg(if threats > 0 { Color::Rgb(255, 80, 80) } else { Color::Rgb(70, 90, 120) }),
        ),
        sep(),
        Span::styled("FW:", Style::default().fg(Color::Rgb(90, 110, 140))),
        Span::styled(format!(" {} ", fw_status), Style::default().fg(fw_color).add_modifier(Modifier::BOLD)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 48, 80)))
        .style(Style::default().bg(Color::Rgb(8, 12, 22)));

    f.render_widget(Paragraph::new(line).block(block), area);
}

/// Render the traffic graph using extended history.
fn draw_traffic_graph(f: &mut Frame, area: Rect, app: &App) {
    let range_samples = app.dashboard_time_range.samples();
    let history = &app.traffic_history;

    // Get recent samples up to the selected range — single allocation, no double-collect
    let len = history.samples.len();
    let take = range_samples.min(len);
    let start = len.saturating_sub(take);
    let data: Vec<(f64, f64)> = history.samples.iter().skip(start).copied().collect();

    draw_traffic_chart(
        f,
        area,
        &data,
        app.dashboard_time_range.label(),
        range_samples,
    );
}

/// Render the world map with per-connection glowing dots.
fn draw_country_map(f: &mut Frame, area: Rect, app: &App) {
    let mut dots: Vec<ConnectionDot> = Vec::new();

    // Color for a connection based on its TCP state
    fn conn_color(state: Option<&TcpState>, is_threat: bool) -> Color {
        if is_threat {
            return Color::Rgb(255, 60, 60); // CLR_THREAT
        }
        match state {
            Some(TcpState::Established) => Color::Rgb(80, 200, 120),   // green
            Some(TcpState::SynSent) | Some(TcpState::SynReceived) => Color::Rgb(60, 180, 255), // cyan
            Some(TcpState::TimeWait) | Some(TcpState::FinWait1) | Some(TcpState::FinWait2) => Color::Rgb(200, 120, 255), // purple
            Some(TcpState::CloseWait) | Some(TcpState::Closing) | Some(TcpState::LastAck) => Color::Rgb(255, 100, 60), // orange
            Some(TcpState::Listen) => Color::Rgb(60, 180, 255),
            _ => Color::Rgb(120, 140, 170), // gray for unknown
        }
    }

    // Live connections → full brightness dots
    for conn in &app.connections {
        if let Some(ip) = conn.remote_addr {
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }
            if let Some(info) = app.geoip.lookup(ip) {
                let is_threat = app.threat_detector.check_ip(ip).is_some();
                dots.push(ConnectionDot {
                    country_code: info.code,
                    color: conn_color(conn.state.as_ref(), is_threat),
                    brightness: 1.0,
                    jitter_seed: ip_to_seed(ip),
                    pulse: matches!(conn.state.as_ref(), Some(TcpState::Established)),
                });
            }
        }
    }

    // Recently-closed connections → fading dots
    for &(ip, code, close_tick) in &app.map_fading_dots {
        let b = fade_brightness(app.tick_count, close_tick);
        if b > 0.0 {
            dots.push(ConnectionDot {
                country_code: code,
                color: Color::Rgb(255, 100, 60), // closing color
                brightness: b,
                jitter_seed: ip_to_seed(ip),
                pulse: false,
            });
        }
    }

    draw_world_map_dots(f, area, &dots, app.tick_count);
}

/// Render the health gauge with computed score.
fn draw_health(f: &mut Frame, area: Rect, app: &App) {
    let active_conns = app
        .connections
        .iter()
        .filter(|c| matches!(c.state.as_ref(), Some(TcpState::Established)))
        .count();

    // Count unique countries
    let mut countries = std::collections::HashSet::new();
    for conn in &app.connections {
        if let Some(ip) = conn.remote_addr {
            if let Some(info) = app.geoip.lookup(ip) {
                countries.insert(info.code);
            }
        }
    }

    let alert_count = app.alert_engine.alerts.len();
    // Count threat-related alerts instead of rescanning (scan requires &mut)
    let threat_count = app.alert_engine.alerts.iter()
        .filter(|a| matches!(a.kind, crate::types::AlertKind::SuspiciousHost { .. }))
        .count();

    let score = compute_health_score(
        active_conns,
        threat_count,
        alert_count,
        app.firewall_manager.enabled,
    );

    draw_health_gauge(
        f,
        area,
        score,
        active_conns,
        countries.len(),
        alert_count,
        threat_count,
    );
}

/// Render the top apps by bandwidth as a bar chart.
fn draw_top_apps(f: &mut Frame, area: Rect, app: &App) {
    let mut apps: Vec<(&String, &crate::types::AppBandwidth)> =
        app.bandwidth_tracker.apps.iter().collect();

    // Sort by total bytes descending
    apps.sort_by(|a, b| {
        let total_a = a.1.download_bytes + a.1.upload_bytes;
        let total_b = b.1.download_bytes + b.1.upload_bytes;
        total_b.cmp(&total_a)
    });

    let entries: Vec<BarEntry> = apps
        .iter()
        .take(8)
        .enumerate()
        .map(|(i, (name, bw))| BarEntry {
            label: name.to_string(),
            value: bw.download_bytes + bw.upload_bytes,
            color: APP_COLORS[i % APP_COLORS.len()],
        })
        .collect();

    draw_bar_chart(f, area, "Top Apps by Bandwidth", &entries);
}
