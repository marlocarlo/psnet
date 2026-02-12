use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;
use crate::types::BottomTab;

pub fn draw_status_bar(f: &mut Frame, area: Rect, app: &App) {
    let common_keys = vec![
        key_span("q", "Quit"),
        key_span("Tab", "Switch"),
        key_span("\u{2191}\u{2193}", "Scroll"),
    ];

    let tab_keys = match app.bottom_tab {
        BottomTab::Connections => vec![
            key_span("1-5", "Sort"),
            key_span("l", &format!("Listen:{}", if app.show_listen { "ON" } else { "OFF" })),
            key_span("x", &format!("{}", if app.hide_localhost_conn { "Show Local" } else { "Hide Local" })),
            key_span("f", "Filter"),
            key_span("Esc", "Clear"),
        ],
        BottomTab::Traffic => vec![
            key_span("p", &format!("{}", if app.traffic_tracker.paused { "Resume" } else { "Pause" })),
            key_span("c", "Clear"),
            key_span("x", &format!("{}", if app.traffic_tracker.hide_localhost { "Show Local" } else { "Hide Local" })),
            key_span("f", "Filter"),
            key_span("Esc", "Clear"),
        ],
    };

    let mut spans = Vec::new();
    for s in common_keys {
        spans.extend(s);
    }
    spans.push(Span::styled(" | ", Style::default().fg(Color::Rgb(50, 60, 80))));
    for s in tab_keys {
        spans.extend(s);
    }

    let paragraph = Paragraph::new(Line::from(spans))
        .style(Style::default().bg(Color::Rgb(14, 20, 36)));
    f.render_widget(paragraph, area);
}

fn key_span(key: &str, desc: &str) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!(" {} ", key),
            Style::default()
                .fg(Color::Rgb(255, 200, 80))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{} ", desc),
            Style::default().fg(Color::Rgb(95, 108, 135)),
        ),
    ]
}
