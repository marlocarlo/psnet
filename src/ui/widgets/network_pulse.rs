//! Network Pulse KPI widget — live packets/sec, unique IPs, data throughput mini-bar.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::utils::{format_bytes, format_speed};

/// Draw a compact network pulse / throughput widget.
pub fn draw_network_pulse(f: &mut Frame, area: Rect, app: &App) {
    let bg = Color::Rgb(8, 12, 24);

    // Compute live metrics
    let devices_online = app.network_scanner.devices.iter().filter(|d| d.is_online).count();
    let total_devices = app.network_scanner.devices.len();
    let unique_countries = {
        let mut set = std::collections::HashSet::new();
        for conn in &app.connections {
            if let Some(ip) = conn.remote_addr {
                if let Some(info) = app.geoip.lookup(ip) {
                    set.insert(info.code);
                }
            }
        }
        set.len()
    };
    let unique_apps = app.bandwidth_tracker.apps.len();
    let (today_down, today_up) = app.usage_tracker.today_usage();

    // Uptime
    let uptime_secs = app.session_start.elapsed().as_secs();
    let uptime_str = if uptime_secs >= 3600 {
        format!("{}h{}m", uptime_secs / 3600, (uptime_secs % 3600) / 60)
    } else if uptime_secs >= 60 {
        format!("{}m{}s", uptime_secs / 60, uptime_secs % 60)
    } else {
        format!("{}s", uptime_secs)
    };

    // Pulsing indicator
    let pulse = if app.current_down_speed > 1000.0 || app.current_up_speed > 1000.0 {
        if app.tick_count % 2 == 0 { "◆" } else { "◇" }
    } else {
        "◇"
    };
    let pulse_color = if app.current_down_speed > 100_000.0 || app.current_up_speed > 100_000.0 {
        Color::Rgb(80, 255, 160)
    } else if app.current_down_speed > 1000.0 || app.current_up_speed > 1000.0 {
        Color::Rgb(80, 200, 120)
    } else {
        Color::Rgb(50, 70, 90)
    };

    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(
                format!(" {} Network Pulse ", pulse),
                Style::default()
                    .fg(pulse_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("up:{} ", uptime_str),
                Style::default().fg(Color::Rgb(80, 100, 130)),
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(bg));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 1 || inner.width < 10 {
        return;
    }

    let mut lines: Vec<Line<'static>> = Vec::new();

    // Row 1: Live throughput with mini sparkline indicator
    let speed_indicator = throughput_bar(
        app.current_down_speed + app.current_up_speed,
        app.peak_down + app.peak_up,
        inner.width.saturating_sub(20) as usize,
    );
    lines.push(Line::from(vec![
        Span::styled(" ▼ ", Style::default().fg(Color::Rgb(80, 200, 255)).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("{:<10}", format_speed(app.current_down_speed)),
            Style::default().fg(Color::Rgb(100, 200, 255)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" ▲ ", Style::default().fg(Color::Rgb(180, 120, 255)).add_modifier(Modifier::BOLD)),
        Span::styled(
            format_speed(app.current_up_speed),
            Style::default().fg(Color::Rgb(200, 140, 255)).add_modifier(Modifier::BOLD),
        ),
    ]));

    // Row 2: throughput bar
    lines.push(Line::from(speed_indicator));

    // Row 3: KPI grid
    lines.push(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(
            format!("{}", devices_online),
            Style::default().fg(Color::Rgb(80, 220, 160)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("/{} dev", total_devices),
            Style::default().fg(Color::Rgb(60, 80, 110)),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(
            format!("{}", unique_countries),
            Style::default().fg(Color::Rgb(255, 200, 80)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " countries",
            Style::default().fg(Color::Rgb(60, 80, 110)),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(
            format!("{}", unique_apps),
            Style::default().fg(Color::Rgb(180, 140, 255)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " apps",
            Style::default().fg(Color::Rgb(60, 80, 110)),
        ),
    ]));

    // Row 4: Today's data
    if inner.height as usize > lines.len() {
        lines.push(Line::from(vec![
            Span::styled(" Today ", Style::default().fg(Color::Rgb(50, 65, 90))),
            Span::styled("▼", Style::default().fg(Color::Rgb(80, 160, 220))),
            Span::styled(
                format!("{} ", format_bytes(today_down)),
                Style::default().fg(Color::Rgb(100, 170, 230)),
            ),
            Span::styled("▲", Style::default().fg(Color::Rgb(160, 100, 220))),
            Span::styled(
                format!("{}", format_bytes(today_up)),
                Style::default().fg(Color::Rgb(180, 140, 240)),
            ),
        ]));
    }

    // Row 5: Firewall + alerts summary
    if inner.height as usize > lines.len() {
        let fw_on = app.firewall_manager.enabled;
        let unread = app.alert_engine.unread();
        lines.push(Line::from(vec![
            Span::styled(" FW:", Style::default().fg(Color::Rgb(50, 65, 90))),
            Span::styled(
                if fw_on { "ON " } else { "OFF" },
                Style::default()
                    .fg(if fw_on { Color::Rgb(80, 200, 120) } else { Color::Rgb(255, 80, 80) })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Alerts:", Style::default().fg(Color::Rgb(50, 65, 90))),
            Span::styled(
                format!("{}", app.alert_engine.alerts.len()),
                Style::default().fg(Color::Rgb(100, 120, 150)),
            ),
            if unread > 0 {
                Span::styled(
                    format!(" ({} new)", unread),
                    Style::default().fg(Color::Rgb(255, 180, 60)).add_modifier(Modifier::BOLD),
                )
            } else {
                Span::styled("", Style::default())
            },
        ]));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(bg));
    f.render_widget(paragraph, inner);
}

/// Build a mini throughput bar showing current vs peak.
fn throughput_bar(current: f64, peak: f64, width: usize) -> Vec<Span<'static>> {
    if width < 4 || peak <= 0.0 {
        return vec![Span::styled(
            "  ░░░░░░░░░░",
            Style::default().fg(Color::Rgb(25, 35, 55)),
        )];
    }
    let pct = (current / peak).min(1.0);
    let filled = (pct * width as f64).round() as usize;
    let empty = width.saturating_sub(filled);

    let fill_color = if pct > 0.8 {
        Color::Rgb(255, 100, 80)
    } else if pct > 0.5 {
        Color::Rgb(255, 200, 80)
    } else if pct > 0.1 {
        Color::Rgb(80, 200, 120)
    } else {
        Color::Rgb(40, 80, 60)
    };

    vec![
        Span::styled(" ", Style::default()),
        Span::styled(
            "█".repeat(filled),
            Style::default().fg(fill_color),
        ),
        Span::styled(
            "░".repeat(empty),
            Style::default().fg(Color::Rgb(25, 35, 55)),
        ),
        Span::styled(
            format!(" {:.0}%", pct * 100.0),
            Style::default().fg(Color::Rgb(70, 85, 110)),
        ),
    ]
}
