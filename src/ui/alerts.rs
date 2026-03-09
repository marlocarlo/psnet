//! Alerts tab UI — GlassWire-style security alerts display.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;

/// Format bytes into human-readable string.
fn fmt_bytes(b: u64) -> String {
    if b >= 1_073_741_824 {
        format!("{:.1} GB", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{} B", b)
    }
}

pub fn draw_alerts(f: &mut Frame, area: Rect, app: &App) {
    // Show "While You Were Away" banner if there's a pending idle summary
    let (_banner_height, table_area) = if let Some(ref summary) = app.alert_engine.idle_tracker.pending_summary {
        let event_lines = summary.events.len().min(3);
        let h = (3 + event_lines) as u16; // header + stats + events
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(h), Constraint::Min(5)])
            .split(area);

        // Render the banner
        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    " While You Were Away ",
                    Style::default()
                        .fg(Color::Rgb(255, 220, 120))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("({}m {}s) ", summary.duration_secs / 60, summary.duration_secs % 60),
                    Style::default().fg(Color::Rgb(150, 170, 200)),
                ),
                Span::styled(
                    "  Press any key to dismiss",
                    Style::default().fg(Color::Rgb(80, 100, 130)),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    format!("  {} new connections", summary.new_connections),
                    Style::default().fg(Color::Rgb(100, 200, 160)),
                ),
                Span::styled("  |  ", Style::default().fg(Color::Rgb(40, 55, 80))),
                Span::styled(
                    format!("Down: {}  Up: {}", fmt_bytes(summary.bytes_down), fmt_bytes(summary.bytes_up)),
                    Style::default().fg(Color::Rgb(130, 170, 220)),
                ),
            ]),
        ];
        for evt in summary.events.iter().take(3) {
            lines.push(Line::from(Span::styled(
                format!("  {}", evt),
                Style::default().fg(Color::Rgb(180, 160, 120)),
            )));
        }

        let banner = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Rgb(80, 70, 30)))
                    .style(Style::default().bg(Color::Rgb(30, 28, 15))),
            );
        f.render_widget(banner, layout[0]);

        (h, layout[1])
    } else {
        (0, area)
    };
    let alerts = &app.alert_engine.alerts;
    let total = alerts.len();

    let visible_height = table_area.height.saturating_sub(5) as usize;
    let selected = if total > 0 { app.alert_engine.scroll_offset.min(total - 1) } else { 0 };

    // Viewport follows selection (centered)
    let viewport_start = if total <= visible_height {
        0
    } else {
        let half = visible_height / 2;
        if selected <= half {
            0
        } else if selected >= total.saturating_sub(half) {
            total.saturating_sub(visible_height)
        } else {
            selected.saturating_sub(half)
        }
    };

    let hdr_style = Style::default()
        .fg(Color::Rgb(160, 180, 220))
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from(Span::styled("", hdr_style)),
        Cell::from(Span::styled("Time", hdr_style)),
        Cell::from(Span::styled("Severity", hdr_style)),
        Cell::from(Span::styled("Type", hdr_style)),
        Cell::from(Span::styled("Description", hdr_style)),
    ])
    .height(1)
    .style(Style::default().bg(Color::Rgb(18, 25, 42)));

    let rows: Vec<Row> = alerts
        .iter()
        .rev()
        .enumerate()
        .skip(viewport_start)
        .take(visible_height)
        .map(|(idx, alert)| {
            let is_selected = idx == selected;
            let time_str = alert.timestamp.format("%H:%M:%S").to_string();
            let severity = alert.kind.severity();
            let sev_color = severity.color();
            let type_label = alert.kind.label();
            let desc = alert.kind.description();

            let row_bg = if is_selected {
                Color::Rgb(25, 45, 85)
            } else if alert.read {
                Color::Rgb(10, 14, 24)
            } else {
                match severity {
                    crate::types::AlertSeverity::Critical => Color::Rgb(30, 12, 12),
                    crate::types::AlertSeverity::Warning => Color::Rgb(28, 24, 12),
                    crate::types::AlertSeverity::Info => Color::Rgb(12, 18, 28),
                }
            };

            let read_dim = if alert.read { Modifier::DIM } else { Modifier::empty() };
            let sev_label = severity.label().to_string();
            let sel_marker = if is_selected { "\u{25B8}" } else { " " };

            Row::new(vec![
                Cell::from(Span::styled(
                    sel_marker,
                    Style::default().fg(Color::Rgb(100, 200, 255)).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    time_str,
                    Style::default().fg(Color::Rgb(100, 110, 130)).add_modifier(read_dim),
                )),
                Cell::from(Span::styled(
                    sev_label,
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD | read_dim),
                )),
                Cell::from(Span::styled(
                    type_label,
                    Style::default().fg(Color::Rgb(180, 190, 220)).add_modifier(read_dim),
                )),
                Cell::from(Span::styled(
                    desc,
                    Style::default().fg(Color::Rgb(150, 160, 180)).add_modifier(read_dim),
                )),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    // Title
    let unread = app.alert_engine.unread();
    let mut title_spans = vec![
        Span::styled(
            " Alerts ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} total ", total),
            Style::default().fg(Color::Rgb(100, 120, 150)),
        ),
    ];
    if unread > 0 {
        title_spans.push(Span::styled(
            format!("({} new) ", unread),
            Style::default().fg(Color::Rgb(255, 100, 80)).add_modifier(Modifier::BOLD),
        ));
    }
    if app.alert_engine.is_snoozed() {
        title_spans.push(Span::styled(
            " SNOOZED ",
            Style::default()
                .fg(Color::Rgb(255, 200, 80))
                .bg(Color::Rgb(60, 50, 20))
                .add_modifier(Modifier::BOLD),
        ));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(1),   // Selection marker
            Constraint::Length(9),   // Time
            Constraint::Length(6),   // Severity
            Constraint::Length(16),  // Type
            Constraint::Min(30),     // Description
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

    f.render_widget(table, table_area);

    // Scrollbar
    if total > visible_height {
        let sb_area = Rect {
            x: table_area.x + table_area.width - 1,
            y: table_area.y + 2,
            width: 1,
            height: table_area.height.saturating_sub(3),
        };
        let mut sb_state =
            ScrollbarState::new(total.saturating_sub(visible_height)).position(viewport_start);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(Color::Rgb(40, 70, 120))),
            sb_area,
            &mut sb_state,
        );
    }
}
