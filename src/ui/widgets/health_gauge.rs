use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Compute and display a network health score.
pub fn draw_health_gauge(f: &mut Frame, area: Rect, score: u8, active_conns: usize, countries: usize, alert_count: usize, threat_count: usize) {
    let (color, label) = match score {
        80..=100 => (Color::Rgb(80, 200, 120), "Excellent"),
        60..=79 => (Color::Rgb(100, 200, 255), "Good"),
        40..=59 => (Color::Rgb(255, 200, 80), "Fair"),
        _ => (Color::Rgb(255, 80, 80), "Poor"),
    };

    // Build a simple gauge bar
    let gauge_width = area.width.saturating_sub(4) as usize;
    let filled = (score as usize * gauge_width) / 100;
    let gauge_bar = format!("{}{}", "█".repeat(filled), "░".repeat(gauge_width.saturating_sub(filled)));

    let lines = vec![
        Line::from(vec![
            Span::styled(
                format!("  Network Health: {} ", score),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("({})", label),
                Style::default().fg(color),
            ),
        ]),
        Line::from(Span::styled(
            format!("  {}", gauge_bar),
            Style::default().fg(color),
        )),
        Line::from(vec![
            Span::styled(format!("  {} ", active_conns), Style::default().fg(Color::Rgb(100, 200, 255)).add_modifier(Modifier::BOLD)),
            Span::styled("conns  ", Style::default().fg(Color::Rgb(80, 100, 130))),
            Span::styled(format!("{} ", countries), Style::default().fg(Color::Rgb(170, 200, 230)).add_modifier(Modifier::BOLD)),
            Span::styled("countries  ", Style::default().fg(Color::Rgb(80, 100, 130))),
            Span::styled(format!("{} ", alert_count), Style::default().fg(Color::Rgb(255, 200, 80)).add_modifier(Modifier::BOLD)),
            Span::styled("alerts  ", Style::default().fg(Color::Rgb(80, 100, 130))),
            if threat_count > 0 {
                Span::styled(format!("{} threats", threat_count), Style::default().fg(Color::Rgb(255, 80, 80)).add_modifier(Modifier::BOLD))
            } else {
                Span::styled("0 threats", Style::default().fg(Color::Rgb(60, 80, 100)))
            },
        ]),
    ];

    let block = Block::default()
        .title(Span::styled(
            " Network Summary ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Compute a health score from app state signals.
pub fn compute_health_score(
    active_conns: usize,
    threat_count: usize,
    alert_count: usize,
    is_firewall_enabled: bool,
) -> u8 {
    let mut score: i32 = 100;

    // Threats are bad
    score -= (threat_count as i32) * 15;

    // Many recent alerts reduce score
    if alert_count > 20 { score -= 15; }
    else if alert_count > 10 { score -= 8; }
    else if alert_count > 5 { score -= 3; }

    // No firewall is risky
    if !is_firewall_enabled { score -= 20; }

    // Too many connections might indicate issues
    if active_conns > 200 { score -= 10; }
    else if active_conns > 100 { score -= 5; }

    // No connections at all is suspicious
    if active_conns == 0 { score -= 5; }

    score.clamp(0, 100) as u8
}
