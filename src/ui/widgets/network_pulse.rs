//! Network Pulse KPI widget — live packets/sec, unique IPs, data throughput mini-bar.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::utils::format_bytes;

/// Draw a compact network pulse / KPI widget.
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

    // Row 1: KPI grid — devices, countries, apps
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

    // Row 2: Today's data
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

    // Row 3: Firewall + alerts summary
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

