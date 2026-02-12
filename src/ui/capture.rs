use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;
use crate::network::dns::port_service_name;
use crate::types::TrafficEventKind;
use crate::ui::connections::tab_title_spans;

pub fn draw_traffic(f: &mut Frame, area: Rect, app: &App) {
    let tracker = &app.traffic_tracker;
    let filtered = tracker.filtered_log();

    // Apply localhost filter
    let filtered: Vec<_> = if tracker.hide_localhost {
        filtered.into_iter().filter(|e| {
            !e.local_addr.is_loopback()
                && !e.remote_addr.map(|a| a.is_loopback()).unwrap_or(false)
        }).collect()
    } else {
        filtered
    };

    let total = filtered.len();

    let visible_height = area.height.saturating_sub(5) as usize;
    let scroll = if tracker.auto_scroll {
        total.saturating_sub(visible_height)
    } else {
        tracker.scroll_offset.min(total.saturating_sub(visible_height))
    };

    let hdr_style = Style::default()
        .fg(Color::Rgb(160, 180, 220))
        .add_modifier(Modifier::BOLD);

    // Columns: Time | Process | Host/Domain | Service | Event | State
    let header = Row::new(vec![
        Cell::from(Span::styled("Time", hdr_style)),
        Cell::from(Span::styled("Process", hdr_style)),
        Cell::from(Span::styled("Host / Domain", hdr_style)),
        Cell::from(Span::styled("Service", hdr_style)),
        Cell::from(Span::styled("Event", hdr_style)),
        Cell::from(Span::styled("State", hdr_style)),
    ])
    .height(1)
    .style(Style::default().bg(Color::Rgb(18, 25, 42)));

    let rows: Vec<Row> = filtered
        .iter()
        .skip(scroll)
        .take(visible_height)
        .map(|entry| {
            let time_str = entry.timestamp.format("%H:%M:%S").to_string();

            // ── Host / Domain column (the star of the show) ──
            let (host_display, host_color) = build_host_display(entry);

            // ── Service column: port + service label + direction ──
            let service_display = build_service_display(entry);

            // ── Event ──
            let event_color = entry.event.color();
            let event_label = match &entry.event {
                TrafficEventKind::NewConnection => "● OPEN",
                TrafficEventKind::ConnectionClosed => "✕ CLOSE",
                TrafficEventKind::StateChange { .. } => "↔ STATE",
            };

            // ── State ──
            let state_detail = match &entry.event {
                TrafficEventKind::StateChange { from, to } => {
                    format!("{} → {}", from.label(), to.label())
                }
                _ => entry.state_label.clone(),
            };
            let state_color = match &entry.event {
                TrafficEventKind::StateChange { to, .. } => to.color(),
                TrafficEventKind::NewConnection => Color::Green,
                TrafficEventKind::ConnectionClosed => Color::Red,
            };

            // ── Process ──
            let process_color = Color::Rgb(150, 200, 150);

            // Row background tint
            let row_bg = match &entry.event {
                TrafficEventKind::NewConnection => Color::Rgb(15, 25, 18),
                TrafficEventKind::ConnectionClosed => Color::Rgb(25, 15, 15),
                TrafficEventKind::StateChange { .. } => Color::Rgb(25, 25, 12),
            };

            Row::new(vec![
                Cell::from(Span::styled(
                    time_str,
                    Style::default().fg(Color::Rgb(100, 110, 130)),
                )),
                Cell::from(Span::styled(
                    entry.process_name.clone(),
                    Style::default().fg(process_color),
                )),
                Cell::from(Span::styled(
                    host_display,
                    Style::default().fg(host_color).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    service_display,
                    Style::default().fg(Color::Rgb(200, 180, 100)),
                )),
                Cell::from(Span::styled(
                    event_label,
                    Style::default().fg(event_color).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    state_detail,
                    Style::default().fg(state_color),
                )),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    // ── Title bar ──
    let filter_info = if tracker.filter_text.is_empty() {
        String::new()
    } else {
        format!(" [filter: {}]", tracker.filter_text)
    };
    let pause_info = if tracker.paused { " ⏸ PAUSED " } else { "" };
    let localhost_info = if tracker.hide_localhost { " 🌐 WAN" } else { " 🔗 ALL" };

    let mut title_spans = tab_title_spans(&app.bottom_tab);
    title_spans.push(Span::styled(
        format!("  {}/{} ", tracker.log.len(), tracker.max_log_size),
        Style::default().fg(Color::Rgb(110, 130, 160)),
    ));
    let usage_pct = (tracker.log.len() as f64 / tracker.max_log_size as f64 * 100.0) as u8;
    let usage_color = if usage_pct > 90 {
        Color::Red
    } else if usage_pct > 70 {
        Color::Yellow
    } else {
        Color::Rgb(80, 140, 80)
    };
    title_spans.push(Span::styled(
        format!("({}%)", usage_pct),
        Style::default().fg(usage_color),
    ));
    title_spans.push(Span::styled(
        localhost_info.to_string(),
        Style::default().fg(Color::Rgb(100, 180, 220)),
    ));
    if !pause_info.is_empty() {
        title_spans.push(Span::styled(
            pause_info.to_string(),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    if !filter_info.is_empty() {
        title_spans.push(Span::styled(filter_info, Style::default().fg(Color::Yellow)));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(9),   // Time
            Constraint::Length(16),  // Process
            Constraint::Min(30),     // Host / Domain (primary column)
            Constraint::Length(14),  // Service
            Constraint::Length(9),   // Event
            Constraint::Min(14),     // State
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Line::from(title_spans))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
            .style(Style::default().bg(Color::Rgb(12, 16, 28))),
    );

    f.render_widget(table, area);

    // Scrollbar
    if total > visible_height {
        let sb_area = Rect {
            x: area.x + area.width - 1,
            y: area.y + 2,
            width: 1,
            height: area.height.saturating_sub(3),
        };
        let mut sb_state =
            ScrollbarState::new(total.saturating_sub(visible_height)).position(scroll);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(Color::Rgb(40, 70, 120))),
            sb_area,
            &mut sb_state,
        );
    }
}

// ─── Helper: build the Host/Domain display string ────────────────────────────

use crate::types::TrafficEntry;

fn build_host_display(entry: &TrafficEntry) -> (String, Color) {
    let dir_arrow = if entry.outbound { "→" } else { "←" };

    match (entry.remote_addr, entry.remote_port) {
        (Some(addr), Some(port)) => {
            if let Some(ref dns) = entry.dns_name {
                // DNS resolved — show domain name prominently
                let display = format!("{} {}:{}", dir_arrow, dns, port);
                (display, Color::Rgb(100, 220, 255)) // Bright cyan
            } else if addr.is_loopback() {
                let display = format!("{} localhost:{}", dir_arrow, port);
                (display, Color::Rgb(100, 100, 120)) // Dim for localhost
            } else {
                // No DNS — show IP:port
                let display = format!("{} {}:{}", dir_arrow, addr, port);
                (display, Color::Rgb(170, 185, 205)) // Normal
            }
        }
        (Some(addr), None) => {
            if let Some(ref dns) = entry.dns_name {
                let display = format!("{} {}", dir_arrow, dns);
                (display, Color::Rgb(100, 220, 255))
            } else {
                let display = format!("{} {}", dir_arrow, addr);
                (display, Color::Rgb(170, 185, 205))
            }
        }
        _ => {
            // Fallback: show local port info if we have it (e.g. UDP bind)
            let local_svc = port_service_name(entry.local_port)
                .map(|s| format!("{} [{}]", entry.local_port, s))
                .unwrap_or_else(|| format!(":{}", entry.local_port));
            (format!("{} {} {}", dir_arrow, entry.local_addr, local_svc), Color::Rgb(120, 120, 150))
        }
    }
}

// ─── Helper: build the Service display string ────────────────────────────────

fn build_service_display(entry: &TrafficEntry) -> String {
    let proto = entry.proto.label();

    // Use remote port if available, otherwise fall back to local port
    let port = entry.remote_port.unwrap_or(entry.local_port);

    if let Some(svc) = port_service_name(port) {
        format!("{}/{}", svc, proto)
    } else if port > 0 {
        format!("{}/{}", port, proto)
    } else {
        proto.to_string()
    }
}
