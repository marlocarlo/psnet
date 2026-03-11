use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::network::protocols::ProtocolTracker;

/// Format a count compactly: 0-999 as-is, 1000+ as "1.2k", 1_000_000+ as "1.2M".
fn compact_count(n: u64) -> String {
    if n >= 1_000_000 {
        let m = n as f64 / 1_000_000.0;
        if m >= 100.0 {
            format!("{}M", m as u64)
        } else if m >= 10.0 {
            format!("{:.0}M", m)
        } else {
            format!("{:.1}M", m)
        }
    } else if n >= 1_000 {
        let k = n as f64 / 1_000.0;
        if k >= 100.0 {
            format!("{}k", k as u64)
        } else if k >= 10.0 {
            format!("{:.0}k", k)
        } else {
            format!("{:.1}k", k)
        }
    } else {
        format!("{}", n)
    }
}

/// Interpolate a protocol color toward dim based on brightness (0.0..1.0).
fn fade_color(base: Color, brightness: f64) -> Color {
    match base {
        Color::Rgb(r, g, b) => {
            let dim_r: u8 = 40;
            let dim_g: u8 = 45;
            let dim_b: u8 = 55;
            let br = brightness.clamp(0.0, 1.0);
            let out_r = dim_r as f64 + (r as f64 - dim_r as f64) * br;
            let out_g = dim_g as f64 + (g as f64 - dim_g as f64) * br;
            let out_b = dim_b as f64 + (b as f64 - dim_b as f64) * br;
            Color::Rgb(out_r as u8, out_g as u8, out_b as u8)
        }
        other => {
            if brightness > 0.3 { other } else { Color::DarkGray }
        }
    }
}

/// Draw the protocol tag cloud widget.
pub fn draw_protocol_cloud(f: &mut Frame, area: Rect, tracker: &ProtocolTracker, tick: u64) {
    let bg = Color::Rgb(8, 12, 24);
    let border_color = Color::Rgb(30, 50, 85);
    let title_color = Color::Rgb(100, 160, 255);

    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" Network Signals ", Style::default().fg(title_color)),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(bg));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.width < 4 || inner.height < 1 {
        return;
    }

    let protos = tracker.active_protocols(tick);
    if protos.is_empty() {
        let empty = Paragraph::new(Line::from(vec![
            Span::styled("  Waiting for packets...", Style::default().fg(Color::Rgb(60, 70, 90))),
        ])).style(Style::default().bg(bg));
        f.render_widget(empty, inner);
        return;
    }

    let max_width = inner.width as usize;
    let max_lines = inner.height as usize;

    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut current_spans: Vec<Span<'static>> = Vec::new();
    let mut current_width: usize = 0;

    for (proto, activity) in &protos {
        let brightness = tracker.brightness(proto, tick);
        let is_active = brightness > 0.0;
        let label = proto.label();
        let count_str = compact_count(activity.count);

        let tag_text = format!("{}:{}", label, count_str);
        let tag_width = tag_text.len() + 1; // +1 for trailing space

        // Wrap to next line if needed
        if current_width + tag_width > max_width && !current_spans.is_empty() {
            lines.push(Line::from(current_spans));
            current_spans = Vec::new();
            current_width = 0;
            if lines.len() >= max_lines {
                break;
            }
        }

        let fg = fade_color(proto.color(), brightness);
        let mut style = Style::default().fg(fg).bg(bg);

        if is_active {
            style = style.add_modifier(ratatui::style::Modifier::BOLD);
        }

        // Recent activity marker: bright dot prefix for very active protocols
        if is_active && activity.recent_count > 0 {
            let dot_brightness = brightness.clamp(0.5, 1.0);
            let dot_color = fade_color(proto.color(), dot_brightness);
            current_spans.push(Span::styled(
                "\u{25CF}".to_string(), // filled circle
                Style::default().fg(dot_color).bg(bg),
            ));
            current_width += 1;
        }

        current_spans.push(Span::styled(tag_text, style));
        current_spans.push(Span::styled(" ".to_string(), Style::default().bg(bg)));
        current_width += tag_width;
    }

    if !current_spans.is_empty() && lines.len() < max_lines {
        lines.push(Line::from(current_spans));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(bg));
    f.render_widget(paragraph, inner);
}
