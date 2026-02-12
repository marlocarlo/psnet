use chrono::Local;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;

pub fn draw_title_bar(f: &mut Frame, area: Rect, app: &App) {
    let now = Local::now().format("%H:%M:%S").to_string();
    let elapsed = app.session_start.elapsed();
    let dur = format!(
        "{}:{:02}:{:02}",
        elapsed.as_secs() / 3600,
        (elapsed.as_secs() % 3600) / 60,
        elapsed.as_secs() % 60
    );

    let conn_count = app.connections.len();
    let established = app
        .connections
        .iter()
        .filter(|c| matches!(c.state.as_ref(), Some(crate::types::TcpState::Established)))
        .count();

    // Activity indicator — pulses based on current throughput
    let activity = if app.current_down_speed > 500_000.0 || app.current_up_speed > 500_000.0 {
        Span::styled(
            " \u{26A1} ",
            Style::default()
                .fg(Color::Rgb(255, 220, 80))
                .add_modifier(Modifier::BOLD),
        )
    } else if app.current_down_speed > 5_000.0 || app.current_up_speed > 5_000.0 {
        Span::styled(
            " \u{25CF} ",
            Style::default().fg(Color::Rgb(80, 200, 120)),
        )
    } else {
        Span::styled(
            " \u{25CB} ",
            Style::default().fg(Color::Rgb(55, 70, 95)),
        )
    };

    let title = Line::from(vec![
        Span::styled(
            " \u{25C8} PSNET ",
            Style::default()
                .fg(Color::Rgb(80, 200, 255))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "Network Monitor",
            Style::default().fg(Color::Rgb(130, 150, 190)),
        ),
        activity,
        Span::styled(
            " \u{2502} ",
            Style::default().fg(Color::Rgb(35, 50, 75)),
        ),
        Span::styled(
            format!("{} ", app.interface_name),
            Style::default().fg(Color::Rgb(90, 150, 210)),
        ),
        Span::styled(
            " \u{2502} ",
            Style::default().fg(Color::Rgb(35, 50, 75)),
        ),
        Span::styled(
            format!("{}", established),
            Style::default()
                .fg(Color::Rgb(80, 200, 120))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" active / {} total ", conn_count),
            Style::default().fg(Color::Rgb(85, 100, 130)),
        ),
        Span::styled(
            " \u{2502} ",
            Style::default().fg(Color::Rgb(35, 50, 75)),
        ),
        Span::styled(
            format!("\u{23F1} {} ", dur),
            Style::default().fg(Color::Rgb(110, 120, 150)),
        ),
        Span::styled(
            format!(" {} ", now),
            Style::default().fg(Color::Rgb(85, 95, 120)),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    f.render_widget(Paragraph::new(title).block(block), area);
}
