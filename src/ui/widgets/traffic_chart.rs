use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders};
use ratatui::widgets::canvas::{Canvas, Line as CanvasLine};
use ratatui::Frame;

/// Draw a time-series line graph of download/upload traffic.
/// `data` is a slice of (down_bps, up_bps) samples, newest last.
/// `time_label` is e.g. "5m" to show in the title.
pub fn draw_traffic_chart(f: &mut Frame, area: Rect, data: &[(f64, f64)], _time_label: &str, selected_range: usize) {
    if area.width < 10 || area.height < 5 || data.is_empty() {
        // Too small, render empty block
        let block = Block::default()
            .title(Span::styled(" Traffic ", Style::default().fg(Color::Rgb(160, 180, 220))))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
            .style(Style::default().bg(Color::Rgb(12, 16, 28)));
        f.render_widget(block, area);
        return;
    }

    // Find the max value for Y-axis scaling
    let max_val = data.iter()
        .flat_map(|(d, u)| [*d, *u])
        .fold(1.0_f64, f64::max);

    let chart_width = (area.width - 2) as f64; // inside borders
    let _chart_height = (area.height - 2) as f64;
    let n = data.len();
    let x_scale = chart_width / n.max(1) as f64;

    // Build title with time range buttons
    let title_spans = vec![
        Span::styled(" Traffic Graph ", Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(ratatui::style::Modifier::BOLD)),
        Span::styled(" │ ", Style::default().fg(Color::Rgb(40, 55, 80))),
        range_btn("5m", 300, selected_range),
        Span::styled(" ", Style::default()),
        range_btn("15m", 900, selected_range),
        Span::styled(" ", Style::default()),
        range_btn("1h", 3600, selected_range),
        Span::styled(" ", Style::default()),
        range_btn("24h", 86400, selected_range),
        Span::styled(" │ ", Style::default().fg(Color::Rgb(40, 55, 80))),
        Span::styled(format!("Peak: {}", fmt_speed(max_val)), Style::default().fg(Color::Rgb(100, 120, 150))),
    ];

    let canvas = Canvas::default()
        .block(
            Block::default()
                .title(ratatui::text::Line::from(title_spans))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
                .style(Style::default().bg(Color::Rgb(8, 12, 24))),
        )
        .x_bounds([0.0, chart_width])
        .y_bounds([0.0, max_val * 1.1])
        .paint(move |ctx| {
            // Draw download line (cyan)
            for i in 1..n {
                let x1 = (i - 1) as f64 * x_scale;
                let x2 = i as f64 * x_scale;
                let y1 = data[i - 1].0;
                let y2 = data[i].0;
                ctx.draw(&CanvasLine {
                    x1, y1, x2, y2,
                    color: Color::Rgb(50, 160, 255),
                });
            }
            // Draw upload line (purple)
            for i in 1..n {
                let x1 = (i - 1) as f64 * x_scale;
                let x2 = i as f64 * x_scale;
                let y1 = data[i - 1].1;
                let y2 = data[i].1;
                ctx.draw(&CanvasLine {
                    x1, y1, x2, y2,
                    color: Color::Rgb(180, 100, 255),
                });
            }
        });

    f.render_widget(canvas, area);
}

fn range_btn(label: &str, samples: usize, selected: usize) -> Span<'static> {
    if samples == selected {
        Span::styled(
            format!("[{}]", label),
            Style::default().fg(Color::Rgb(255, 220, 120)).add_modifier(ratatui::style::Modifier::BOLD),
        )
    } else {
        Span::styled(
            format!(" {} ", label),
            Style::default().fg(Color::Rgb(80, 100, 130)),
        )
    }
}

fn fmt_speed(bps: f64) -> String {
    if bps >= 1_000_000_000.0 { format!("{:.1} GB/s", bps / 1_000_000_000.0) }
    else if bps >= 1_000_000.0 { format!("{:.1} MB/s", bps / 1_000_000.0) }
    else if bps >= 1_000.0 { format!("{:.1} KB/s", bps / 1_000.0) }
    else { format!("{:.0} B/s", bps) }
}
