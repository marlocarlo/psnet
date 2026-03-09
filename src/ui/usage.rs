//! Usage / Bandwidth per-app tab UI.
//!
//! Shows per-application bandwidth consumption with mini-sparklines,
//! data plan status, and daily usage summary.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;
use crate::utils::{format_bytes, format_speed};

pub fn draw_usage(f: &mut Frame, area: Rect, app: &App) {
    let apps = app.bandwidth_tracker.sorted_apps();
    let total_apps = apps.len();

    let title_spans = vec![
        Span::styled(
            " Usage ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} apps tracked ", total_apps),
            Style::default().fg(Color::Rgb(100, 120, 150)),
        ),
    ];

    let outer_block = Block::default()
        .title(Line::from(title_spans))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(12, 16, 28)));
    let inner = outer_block.inner(area);
    f.render_widget(outer_block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),  // Data plan summary
            Constraint::Min(6),     // Per-app bandwidth table
        ])
        .split(inner);

    draw_data_plan_summary(f, chunks[0], app);
    draw_per_app_table(f, chunks[1], app, apps);
}

fn draw_data_plan_summary(f: &mut Frame, area: Rect, app: &App) {
    let (today_down, today_up) = app.usage_tracker.today_usage();
    let (month_down, month_up) = app.usage_tracker.month_usage();
    let (used, limit, pct) = app.usage_tracker.plan_status();

    let plan_info = if limit > 0 {
        let gauge_width = 20u16;
        let filled = ((pct as f64 / 100.0) * gauge_width as f64).round() as u16;
        let empty = gauge_width.saturating_sub(filled);
        let gauge_color = if pct > 90 { Color::Red } else if pct > 70 { Color::Yellow } else { Color::Rgb(50, 200, 120) };

        vec![
            Line::from(vec![
                Span::styled("  Data Plan: ", Style::default().fg(Color::Rgb(120, 140, 170))),
                Span::styled(
                    format!("{} / {} ", format_bytes(used), format_bytes(limit)),
                    Style::default().fg(Color::Rgb(180, 200, 230)).add_modifier(Modifier::BOLD),
                ),
                Span::styled("█".repeat(filled as usize), Style::default().fg(gauge_color)),
                Span::styled("░".repeat(empty as usize), Style::default().fg(Color::Rgb(30, 40, 55))),
                Span::styled(format!(" {}%", pct), Style::default().fg(gauge_color)),
            ]),
            Line::from(vec![
                Span::styled("  Today: ", Style::default().fg(Color::Rgb(80, 100, 130))),
                Span::styled(
                    format!("▼{} ▲{}", format_bytes(today_down), format_bytes(today_up)),
                    Style::default().fg(Color::Rgb(130, 160, 200)),
                ),
                Span::styled("  │  Month: ", Style::default().fg(Color::Rgb(80, 100, 130))),
                Span::styled(
                    format!("▼{} ▲{}", format_bytes(month_down), format_bytes(month_up)),
                    Style::default().fg(Color::Rgb(130, 160, 200)),
                ),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![
                Span::styled("  No data plan configured", Style::default().fg(Color::Rgb(80, 100, 130))),
            ]),
            Line::from(vec![
                Span::styled("  Today: ", Style::default().fg(Color::Rgb(80, 100, 130))),
                Span::styled(
                    format!("▼{} ▲{}", format_bytes(today_down), format_bytes(today_up)),
                    Style::default().fg(Color::Rgb(130, 160, 200)),
                ),
                Span::styled("  │  Month: ", Style::default().fg(Color::Rgb(80, 100, 130))),
                Span::styled(
                    format!("▼{} ▲{}", format_bytes(month_down), format_bytes(month_up)),
                    Style::default().fg(Color::Rgb(130, 160, 200)),
                ),
            ]),
        ]
    };

    let block = Block::default()
        .title(Span::styled(
            " 📊 Data Plan ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    f.render_widget(Paragraph::new(plan_info).block(block), area);
}

fn draw_per_app_table(f: &mut Frame, area: Rect, app: &App, apps: Vec<&crate::types::AppBandwidth>) {
    let total = apps.len();
    let visible_height = area.height.saturating_sub(2) as usize;
    let selected = if total > 0 { app.usage_scroll.min(total - 1) } else { 0 };

    let hdr_style = Style::default()
        .fg(Color::Rgb(160, 180, 220))
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from(Span::styled("Application", hdr_style)),
        Cell::from(Span::styled("↓ Download", hdr_style)),
        Cell::from(Span::styled("↑ Upload", hdr_style)),
        Cell::from(Span::styled("Total", hdr_style)),
        Cell::from(Span::styled("Conns", hdr_style)),
        Cell::from(Span::styled("Speed", hdr_style)),
    ])
    .height(1)
    .style(Style::default().bg(Color::Rgb(18, 25, 42)));

    let rows: Vec<Row> = apps
        .iter()
        .enumerate()
        .take(visible_height)
        .map(|(idx, bw)| {
            let is_selected = idx == selected;
            let current_down = bw.recent_down.back().copied().unwrap_or(0.0);
            let current_up = bw.recent_up.back().copied().unwrap_or(0.0);
            let speed_str = if current_down + current_up > 0.0 {
                format!("▼{} ▲{}", format_speed(current_down), format_speed(current_up))
            } else {
                "idle".to_string()
            };

            let speed_color = if current_down + current_up > 100_000.0 {
                Color::Rgb(80, 220, 160)
            } else if current_down + current_up > 1000.0 {
                Color::Rgb(100, 160, 200)
            } else {
                Color::Rgb(70, 80, 100)
            };

            let active = bw.active_connections > 0;
            let row_bg = if is_selected {
                Color::Rgb(25, 45, 85)
            } else if active {
                Color::Rgb(14, 18, 30)
            } else {
                Color::Rgb(10, 12, 22)
            };

            let name_display = if is_selected {
                format!("\u{25B8} {}", bw.process_name)
            } else {
                format!("  {}", bw.process_name)
            };

            Row::new(vec![
                Cell::from(Span::styled(
                    name_display,
                    Style::default().fg(if active { Color::Rgb(130, 200, 140) } else { Color::Rgb(80, 95, 115) }),
                )),
                Cell::from(Span::styled(
                    format_bytes(bw.download_bytes),
                    Style::default().fg(Color::Rgb(80, 180, 255)),
                )),
                Cell::from(Span::styled(
                    format_bytes(bw.upload_bytes),
                    Style::default().fg(Color::Rgb(180, 120, 255)),
                )),
                Cell::from(Span::styled(
                    format_bytes(bw.total_bytes()),
                    Style::default().fg(Color::Rgb(170, 185, 210)).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    bw.active_connections.to_string(),
                    Style::default().fg(if active { Color::Rgb(80, 200, 120) } else { Color::Rgb(60, 70, 85) }),
                )),
                Cell::from(Span::styled(
                    speed_str,
                    Style::default().fg(speed_color),
                )),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),  // Application
            Constraint::Length(12),  // Download
            Constraint::Length(12),  // Upload
            Constraint::Length(12),  // Total
            Constraint::Length(6),   // Connections
            Constraint::Min(20),     // Speed
        ],
    )
    .header(header);

    f.render_widget(table, area);

    // Scrollbar
    if total > visible_height {
        let sb_area = Rect {
            x: area.x + area.width - 1,
            y: area.y + 2,
            width: 1,
            height: area.height.saturating_sub(3),
        };
        let mut sb_state = ScrollbarState::new(total.saturating_sub(visible_height)).position(0);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(Color::Rgb(40, 70, 120))),
            sb_area,
            &mut sb_state,
        );
    }
}
