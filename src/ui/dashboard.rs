//! Dashboard tab — GlassWire-style overview with traffic graph, world map,
//! top apps bar chart, and network health summary.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::types::TcpState;

use super::widgets::bar_chart::{draw_bar_chart, BarEntry};
use super::widgets::health_gauge::compute_health_score;
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
                Constraint::Min(10),  // Full map
                Constraint::Length(1), // Footer hint
            ])
            .split(area);

        draw_country_map(f, main_split[0], app);

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
            main_split[1],
        );
        return;
    }

    // ── Layout: traffic graph + countries (top) → map + right panels (bottom) ──
    let main_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(50), // Traffic graph + top countries
            Constraint::Percentage(50), // Bottom panels
        ])
        .split(area);

    // Middle row: traffic graph on left, top countries on right
    let mid_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(70), // Traffic graph
            Constraint::Percentage(30), // Top 10 countries
        ])
        .split(main_split[0]);

    let bottom_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(55), // World map
            Constraint::Percentage(45), // Health + top apps
        ])
        .split(main_split[1]);

    let right_split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Health + connection sparkline
            Constraint::Min(5),   // Top apps bar chart
        ])
        .split(bottom_split[1]);

    // ── Draw all widgets ──
    draw_traffic_graph(f, mid_split[0], app);
    draw_top_countries(f, mid_split[1], app);
    draw_country_map(f, bottom_split[0], app);
    draw_health_sparkline(f, right_split[0], app);
    draw_top_apps(f, right_split[1], app);
}

// ─── Health + connection sparkline ────────────────────────────────────────────

fn draw_health_sparkline(f: &mut Frame, area: Rect, app: &App) {
    let active = app.connections.iter()
        .filter(|c| matches!(c.state.as_ref(), Some(TcpState::Established)))
        .count();
    let threats = app.alert_engine.alerts.iter()
        .filter(|a| matches!(a.kind, crate::types::AlertKind::SuspiciousHost { .. }))
        .count();
    let alert_count = app.alert_engine.alerts.len();
    let health = compute_health_score(active, threats, alert_count, app.firewall_manager.enabled);

    let (health_color, health_label) = match health {
        80..=100 => (Color::Rgb(80, 200, 120), "Excellent"),
        60..=79 => (Color::Rgb(100, 200, 255), "Good"),
        40..=59 => (Color::Rgb(255, 200, 80), "Fair"),
        _ => (Color::Rgb(255, 80, 80), "Poor"),
    };

    // Health gauge bar
    let gauge_w = area.width.saturating_sub(4) as usize;
    let filled = (health as usize * gauge_w) / 100;
    let gauge_bar = format!("{}{}", "█".repeat(filled), "░".repeat(gauge_w.saturating_sub(filled)));

    let dim = Style::default().fg(Color::Rgb(70, 90, 120));

    let line1 = Line::from(vec![
        Span::styled(
            format!("  Health: {} ", health),
            Style::default().fg(health_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(health_label, Style::default().fg(health_color)),
        Span::styled("   IPs: ", dim),
        Span::styled(
            format!("{}", app.connections.iter()
                .filter_map(|c| c.remote_addr)
                .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
                .collect::<std::collections::HashSet<_>>().len()),
            Style::default().fg(Color::Rgb(140, 170, 210)).add_modifier(Modifier::BOLD),
        ),
    ]);

    let line2 = Line::from(Span::styled(format!("  {}", gauge_bar), Style::default().fg(health_color)));

    // Connection count sparkline
    let spark_width = area.width.saturating_sub(14) as usize;
    let hist = &app.connection_count_history;
    let take = spark_width.min(hist.len());
    let start = hist.len().saturating_sub(take);
    let sparkline = if take > 0 {
        let samples: Vec<u64> = hist.iter().skip(start).copied().collect();
        let max_val = samples.iter().copied().max().unwrap_or(1).max(1);
        let chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
        samples.iter().map(|&v| {
            let idx = ((v as f64 / max_val as f64) * 7.0) as usize;
            chars[idx.min(7)]
        }).collect()
    } else {
        "▁".repeat(spark_width.max(1))
    };

    let line3 = Line::from(vec![
        Span::styled("  Conns ▏", dim),
        Span::styled(sparkline, Style::default().fg(Color::Rgb(80, 160, 220))),
    ]);

    let block = Block::default()
        .title(Span::styled(
            " Network Health ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    f.render_widget(Paragraph::new(vec![line1, line2, line3]).block(block), area);
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

/// Render the top 10 countries by connection count with country code badges.
fn draw_top_countries(f: &mut Frame, area: Rect, app: &App) {
    // Tally connections per country
    let mut counts: std::collections::HashMap<&str, (/* code */ &str, /* name */ &str, usize)> =
        std::collections::HashMap::new();
    for conn in &app.connections {
        if let Some(ip) = conn.remote_addr {
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }
            if let Some(info) = app.geoip.lookup(ip) {
                let entry = counts.entry(info.code).or_insert((info.code, info.name, 0));
                entry.2 += 1;
            }
        }
    }

    let mut sorted: Vec<_> = counts.into_values().collect();
    sorted.sort_by(|a, b| b.2.cmp(&a.2));

    let block = Block::default()
        .title(Span::styled(
            " Top Countries ",
            Style::default()
                .fg(Color::Rgb(160, 180, 220))
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let max_count = sorted.first().map(|e| e.2).unwrap_or(1).max(1);
    // code(2) + space + name(12) + space + count(3) + space + bar
    let bar_budget = inner.width.saturating_sub(21) as usize;

    for (i, (code, name, count)) in sorted.iter().take(10).enumerate() {
        if i as u16 >= inner.height {
            break;
        }
        let row_area = Rect::new(inner.x, inner.y + i as u16, inner.width, 1);

        // Mini bar proportional to max
        let bar_len = if bar_budget > 0 {
            ((*count as f64 / max_count as f64) * bar_budget as f64).ceil() as usize
        } else {
            0
        };

        let color = COUNTRY_COLORS[i % COUNTRY_COLORS.len()];
        let bar_str: String = "█".repeat(bar_len);

        let line = Line::from(vec![
            Span::styled(
                format!(" {} ", code),
                Style::default().fg(Color::Rgb(20, 20, 30)).bg(color),
            ),
            Span::styled(" ", Style::default()),
            Span::styled(
                format!("{:<12}", truncate_name(name, 12)),
                Style::default().fg(Color::Rgb(160, 175, 200)),
            ),
            Span::styled(
                format!("{:>3} ", count),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(bar_str, Style::default().fg(color)),
        ]);

        f.render_widget(Paragraph::new(line), row_area);
    }

    if sorted.is_empty() {
        let msg = Line::from(Span::styled(
            "  No geo data yet",
            Style::default().fg(Color::Rgb(60, 75, 100)),
        ));
        f.render_widget(Paragraph::new(msg), inner);
    }
}

fn truncate_name(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let end = s.char_indices()
            .nth(max.saturating_sub(1))
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        format!("{}…", &s[..end])
    } else {
        s.to_string()
    }
}

const COUNTRY_COLORS: [Color; 10] = [
    Color::Rgb(80, 200, 255),   // cyan
    Color::Rgb(120, 220, 140),  // green
    Color::Rgb(255, 200, 80),   // gold
    Color::Rgb(200, 140, 255),  // lavender
    Color::Rgb(255, 140, 100),  // coral
    Color::Rgb(100, 220, 200),  // teal
    Color::Rgb(255, 160, 200),  // pink
    Color::Rgb(180, 200, 130),  // lime
    Color::Rgb(140, 180, 255),  // periwinkle
    Color::Rgb(220, 180, 140),  // sand
];

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
