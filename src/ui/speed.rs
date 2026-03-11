use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Sparkline};
use ratatui::Frame;

use crate::app::App;
use crate::utils::{format_bytes, format_speed};

use super::widgets::conn_stats::{draw_conn_stats, ConnStats};
use super::widgets::data_rates::draw_data_rates;
use super::widgets::network_pulse::draw_network_pulse;
use super::widgets::protocol_cloud::draw_protocol_cloud;

/// Header section: sparklines (left 40%) + 4 KPI widgets (right 60%).
pub fn draw_speed_section(f: &mut Frame, area: Rect, app: &App) {
    let h_split = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(35), // Sparklines (download + upload stacked)
            Constraint::Percentage(20), // Protocol cloud
            Constraint::Percentage(20), // Connection stats
            Constraint::Percentage(25), // Network pulse + Live rates
        ])
        .split(area);

    draw_sparklines(f, h_split[0], app);
    draw_protocol_cloud(f, h_split[1], &app.protocol_tracker, app.tick_count);

    let conn_stats = ConnStats::from_connections(&app.connections);
    draw_conn_stats(f, h_split[2], &conn_stats, app.tick_count);

    // Right column: pulse on top, live rates on bottom
    let right_col = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(55), // Network pulse
            Constraint::Percentage(45), // Live rates
        ])
        .split(h_split[3]);

    draw_network_pulse(f, right_col[0], app);
    draw_data_rates(f, right_col[1], app);
}

// ─── Sparkline graphs ────────────────────────────────────────────────────────

fn draw_sparklines(f: &mut Frame, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // ── Download sparkline ──
    let down_inner_w = chunks[0].width.saturating_sub(2) as usize;
    let down_data: Vec<u64> = {
        let raw: Vec<u64> = app.speed_history.download.iter()
            .map(|&v| v.max(0.0) as u64)
            .collect();
        if raw.len() < down_inner_w {
            let mut padded = vec![0u64; down_inner_w - raw.len()];
            padded.extend(raw);
            padded
        } else {
            raw[raw.len() - down_inner_w..].to_vec()
        }
    };
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
                        format_speed(app.current_down_speed),
                        Style::default()
                            .fg(Color::Rgb(80, 210, 255))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "  pk:",
                        Style::default().fg(Color::Rgb(55, 65, 85)),
                    ),
                    Span::styled(
                        format_speed(app.peak_down),
                        Style::default().fg(Color::Rgb(100, 120, 160)),
                    ),
                    Span::styled(
                        "  tot:",
                        Style::default().fg(Color::Rgb(55, 65, 85)),
                    ),
                    Span::styled(
                        format!("{} ", format_bytes(app.total_down)),
                        Style::default().fg(Color::Rgb(100, 120, 160)),
                    ),
                ]))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
                .style(Style::default().bg(Color::Rgb(8, 12, 24))),
        );
    f.render_widget(down_sparkline, chunks[0]);

    // ── Upload sparkline ──
    let up_inner_w = chunks[1].width.saturating_sub(2) as usize;
    let up_data: Vec<u64> = {
        let raw: Vec<u64> = app.speed_history.upload.iter()
            .map(|&v| v.max(0.0) as u64)
            .collect();
        if raw.len() < up_inner_w {
            let mut padded = vec![0u64; up_inner_w - raw.len()];
            padded.extend(raw);
            padded
        } else {
            raw[raw.len() - up_inner_w..].to_vec()
        }
    };
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
                        format_speed(app.current_up_speed),
                        Style::default()
                            .fg(Color::Rgb(210, 160, 255))
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        "  pk:",
                        Style::default().fg(Color::Rgb(55, 65, 85)),
                    ),
                    Span::styled(
                        format_speed(app.peak_up),
                        Style::default().fg(Color::Rgb(100, 120, 160)),
                    ),
                    Span::styled(
                        "  tot:",
                        Style::default().fg(Color::Rgb(55, 65, 85)),
                    ),
                    Span::styled(
                        format!("{} ", format_bytes(app.total_up)),
                        Style::default().fg(Color::Rgb(100, 120, 160)),
                    ),
                ]))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
                .style(Style::default().bg(Color::Rgb(8, 12, 24))),
        );
    f.render_widget(up_sparkline, chunks[1]);
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
