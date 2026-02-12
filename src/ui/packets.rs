use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::network::sniffer::PacketSniffer;
use crate::types::PacketDirection;

pub fn draw_packet_preview(f: &mut Frame, area: Rect, sniffer: &PacketSniffer) {
    let visible_lines = area.height.saturating_sub(2) as usize; // borders

    // Check for error state
    if let Some(err) = sniffer.get_error() {
        let lines = vec![Line::from(vec![
            Span::styled(
                "  \u{26A0} ",
                Style::default()
                    .fg(Color::Rgb(200, 160, 60))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                err,
                Style::default().fg(Color::Rgb(140, 120, 80)),
            ),
            Span::styled(
                "  \u{2502}  Run as Administrator to enable packet inspection",
                Style::default().fg(Color::Rgb(80, 90, 110)),
            ),
        ])];

        let block = Block::default()
            .title(wire_title(false))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
            .style(Style::default().bg(Color::Rgb(8, 12, 24)));

        f.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }

    // Get recent snippets
    let recent = sniffer.recent(visible_lines);

    let lines: Vec<Line> = if recent.is_empty() {
        vec![Line::from(Span::styled(
            "  Listening for readable packet data...",
            Style::default().fg(Color::Rgb(60, 75, 100)),
        ))]
    } else {
        recent
            .iter()
            .map(|pkt| {
                let time = pkt.timestamp.format("%H:%M:%S").to_string();

                let (dir_icon, dir_color) = match pkt.direction {
                    PacketDirection::Inbound => (
                        "\u{25C0} IN ",
                        Color::Rgb(80, 200, 120),
                    ),
                    PacketDirection::Outbound => (
                        "\u{25B6} OUT",
                        Color::Rgb(100, 160, 255),
                    ),
                };

                // Truncate snippet to fit the pane width (char-safe)
                let max_snippet_len = area.width.saturating_sub(36) as usize;
                let snippet_display = if pkt.snippet.chars().count() > max_snippet_len {
                    let truncated: String = pkt.snippet.chars().take(max_snippet_len.saturating_sub(3)).collect();
                    format!("{}...", truncated)
                } else {
                    pkt.snippet.clone()
                };

                // Classify payload color
                let snippet_color = classify_snippet_color(&pkt.snippet);

                Line::from(vec![
                    Span::styled(
                        format!(" {} ", time),
                        Style::default().fg(Color::Rgb(65, 75, 100)),
                    ),
                    Span::styled(
                        format!("{} ", dir_icon),
                        Style::default()
                            .fg(dir_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{:>5} ", format_size_compact(pkt.payload_size)),
                        Style::default().fg(Color::Rgb(100, 100, 130)),
                    ),
                    Span::styled(snippet_display, Style::default().fg(snippet_color)),
                ])
            })
            .collect()
    };

    let block = Block::default()
        .title(wire_title(true))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(6, 10, 20)));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Title for the wire preview pane.
fn wire_title(active: bool) -> Line<'static> {
    if active {
        Line::from(vec![
            Span::styled(
                " \u{26A1} Wire ",
                Style::default()
                    .fg(Color::Rgb(255, 200, 80))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Live Packet Preview ",
                Style::default().fg(Color::Rgb(120, 135, 165)),
            ),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                " \u{26A1} Wire ",
                Style::default()
                    .fg(Color::Rgb(120, 100, 60))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Packet Preview (Inactive) ",
                Style::default().fg(Color::Rgb(80, 85, 100)),
            ),
        ])
    }
}

/// Classify snippet content to pick a color.
fn classify_snippet_color(snippet: &str) -> Color {
    let upper = snippet.to_uppercase();
    if upper.starts_with("HTTP/") || upper.starts_with("GET ") || upper.starts_with("POST ")
        || upper.starts_with("PUT ") || upper.starts_with("DELETE ")
        || upper.starts_with("HEAD ") || upper.starts_with("OPTIONS ")
        || upper.starts_with("PATCH ")
    {
        Color::Rgb(80, 220, 160) // Green for HTTP
    } else if upper.starts_with("SSH-") || upper.starts_with("EHLO ") || upper.starts_with("HELO ") {
        Color::Rgb(180, 140, 255) // Purple for protocols
    } else if snippet.starts_with('{') || snippet.starts_with('[') {
        Color::Rgb(100, 200, 255) // Cyan for JSON
    } else if upper.contains("<!DOCTYPE") || upper.contains("<HTML") || upper.contains("<?XML") {
        Color::Rgb(220, 180, 80) // Yellow for HTML/XML
    } else if upper.contains("CONTENT-TYPE") || upper.contains("USER-AGENT")
        || upper.contains("ACCEPT") || upper.contains("HOST:")
    {
        Color::Rgb(140, 200, 160) // Lighter green for HTTP headers
    } else {
        Color::Rgb(130, 140, 165) // Default gray for mixed/unclear
    }
}

/// Compact size display.
fn format_size_compact(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.0}K", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    }
}
