use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline};
use ratatui::Frame;

use crate::app::App;
use crate::utils::{format_bytes, format_speed};

pub fn draw_speed_section(f: &mut Frame, area: Rect, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    draw_sparklines(f, layout[0], app);
    draw_dashboard(f, layout[1], app);
}

// ─── Sparkline graphs ────────────────────────────────────────────────────────

fn draw_sparklines(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // ── Download sparkline ──
    let down_data: Vec<u64> = app.speed_history.download.iter()
        .map(|&v| v.max(0.0) as u64)
        .collect();
    let down_max = down_data.iter().copied().max().unwrap_or(1).max(1);
    let down_color = speed_color(app.current_down_speed);

    let down_sparkline = Sparkline::default()
        .data(&down_data)
        .max(down_max)
        .style(Style::default().fg(down_color))
        .block(
            Block::default()
                .title(Line::from(vec![
                    Span::styled(
                        " ▼ ",
                        Style::default()
                            .fg(Color::Rgb(50, 160, 255))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "Download ",
                        Style::default().fg(Color::Rgb(120, 150, 200)),
                    ),
                    Span::styled(
                        format_speed(app.current_down_speed),
                        Style::default()
                            .fg(Color::Rgb(80, 210, 255))
                            .add_modifier(Modifier::BOLD),
                    ),
                ]))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
                .style(Style::default().bg(Color::Rgb(8, 12, 24))),
        );
    f.render_widget(down_sparkline, chunks[0]);

    // ── Upload sparkline ──
    let up_data: Vec<u64> = app.speed_history.upload.iter()
        .map(|&v| v.max(0.0) as u64)
        .collect();
    let up_max = up_data.iter().copied().max().unwrap_or(1).max(1);
    let up_color = speed_color_warm(app.current_up_speed);

    let up_sparkline = Sparkline::default()
        .data(&up_data)
        .max(up_max)
        .style(Style::default().fg(up_color))
        .block(
            Block::default()
                .title(Line::from(vec![
                    Span::styled(
                        " ▲ ",
                        Style::default()
                            .fg(Color::Rgb(180, 100, 255))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "Upload ",
                        Style::default().fg(Color::Rgb(155, 140, 200)),
                    ),
                    Span::styled(
                        format_speed(app.current_up_speed),
                        Style::default()
                            .fg(Color::Rgb(210, 160, 255))
                            .add_modifier(Modifier::BOLD),
                    ),
                ]))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
                .style(Style::default().bg(Color::Rgb(8, 12, 24))),
        );
    f.render_widget(up_sparkline, chunks[1]);
}

// ─── Dashboard panel ─────────────────────────────────────────────────────────

fn draw_dashboard(f: &mut Frame, area: Rect, app: &App) {
    let down_pct = if app.peak_down > 0.0 {
        (app.current_down_speed / app.peak_down * 100.0).min(100.0) as u16
    } else {
        0
    };
    let up_pct = if app.peak_up > 0.0 {
        (app.current_up_speed / app.peak_up * 100.0).min(100.0) as u16
    } else {
        0
    };

    let gauge_width: u16 = (area.width.saturating_sub(12)).min(20);

    let lines = vec![
        Line::from(""),
        // ── Download ──
        Line::from(vec![
            Span::styled(
                "  ▼ ",
                Style::default()
                    .fg(Color::Rgb(50, 160, 255))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format_speed(app.current_down_speed),
                Style::default()
                    .fg(Color::Rgb(80, 210, 255))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(render_gauge(
            down_pct,
            gauge_width,
            Color::Rgb(50, 160, 255),
            Color::Rgb(25, 35, 55),
        )),
        Line::from(vec![
            Span::styled("  peak ", Style::default().fg(Color::Rgb(55, 65, 85))),
            Span::styled(
                format_speed(app.peak_down),
                Style::default().fg(Color::Rgb(100, 120, 160)),
            ),
            Span::styled("  total ", Style::default().fg(Color::Rgb(55, 65, 85))),
            Span::styled(
                format_bytes(app.total_down),
                Style::default().fg(Color::Rgb(100, 120, 160)),
            ),
        ]),
        Line::from(""),
        // ── Upload ──
        Line::from(vec![
            Span::styled(
                "  ▲ ",
                Style::default()
                    .fg(Color::Rgb(180, 100, 255))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format_speed(app.current_up_speed),
                Style::default()
                    .fg(Color::Rgb(210, 160, 255))
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(render_gauge(
            up_pct,
            gauge_width,
            Color::Rgb(180, 100, 255),
            Color::Rgb(30, 25, 50),
        )),
        Line::from(vec![
            Span::styled("  peak ", Style::default().fg(Color::Rgb(55, 65, 85))),
            Span::styled(
                format_speed(app.peak_up),
                Style::default().fg(Color::Rgb(100, 120, 160)),
            ),
            Span::styled("  total ", Style::default().fg(Color::Rgb(55, 65, 85))),
            Span::styled(
                format_bytes(app.total_up),
                Style::default().fg(Color::Rgb(100, 120, 160)),
            ),
        ]),
    ];

    let block = Block::default()
        .title(Span::styled(
            " Dashboard ",
            Style::default()
                .fg(Color::Rgb(160, 180, 220))
                .add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ─── Gauge bar rendering ─────────────────────────────────────────────────────

fn render_gauge(pct: u16, width: u16, fill_color: Color, empty_color: Color) -> Vec<Span<'static>> {
    let filled = ((pct as f64 / 100.0) * width as f64).round() as u16;
    let empty = width.saturating_sub(filled);

    let mut spans = vec![Span::raw("  ")];
    if filled > 0 {
        spans.push(Span::styled(
            "█".repeat(filled as usize),
            Style::default().fg(fill_color),
        ));
    }
    if empty > 0 {
        spans.push(Span::styled(
            "░".repeat(empty as usize),
            Style::default().fg(empty_color),
        ));
    }
    spans.push(Span::styled(
        format!(" {}%", pct),
        Style::default().fg(Color::Rgb(80, 95, 120)),
    ));

    spans
}

// ─── Dynamic speed colors ────────────────────────────────────────────────────

/// Blue gradient based on download speed
fn speed_color(speed: f64) -> Color {
    if speed > 1_000_000.0 {
        Color::Rgb(0, 255, 255) // Bright cyan for MB/s+
    } else if speed > 100_000.0 {
        Color::Rgb(30, 190, 255)
    } else if speed > 10_000.0 {
        Color::Rgb(50, 140, 230)
    } else {
        Color::Rgb(40, 110, 200) // Dim blue for idle
    }
}

/// Purple gradient based on upload speed
fn speed_color_warm(speed: f64) -> Color {
    if speed > 1_000_000.0 {
        Color::Rgb(255, 130, 255) // Bright magenta
    } else if speed > 100_000.0 {
        Color::Rgb(210, 120, 255)
    } else if speed > 10_000.0 {
        Color::Rgb(170, 100, 230)
    } else {
        Color::Rgb(140, 80, 200) // Dim purple for idle
    }
}
