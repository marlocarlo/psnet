//! Alerts tab UI — categorized security alerts in split panes.
//! Each category gets its own bordered pane with independent scrolling.
//! Keyboard: Left/Right to switch focused pane, Up/Down to scroll within.
//! Mouse: click to focus pane, scroll wheel to scroll within.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Wrap,
};
use ratatui::Frame;

use crate::app::App;
use crate::types::{Alert, AlertCategory};

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

/// Collect alerts for a given category, newest first.
fn alerts_for_category<'a>(alerts: &'a [Alert], cat: AlertCategory) -> Vec<&'a Alert> {
    let mut v: Vec<&Alert> = alerts.iter().filter(|a| a.kind.category() == cat).collect();
    v.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    v
}

/// Get the list of non-empty categories (in display order).
pub fn active_categories(alerts: &[Alert]) -> Vec<AlertCategory> {
    AlertCategory::all()
        .iter()
        .copied()
        .filter(|cat| alerts.iter().any(|a| a.kind.category() == *cat))
        .collect()
}

/// Category ordinal (index into the fixed 6-element array).
fn cat_ordinal(cat: AlertCategory) -> usize {
    match cat {
        AlertCategory::Security => 0,
        AlertCategory::NetworkAccess => 1,
        AlertCategory::SystemChanges => 2,
        AlertCategory::DeviceActivity => 3,
        AlertCategory::Bandwidth => 4,
        AlertCategory::Connectivity => 5,
    }
}

pub fn draw_alerts(f: &mut Frame, area: Rect, app: &mut App) {
    // Show "Since Your Last Visit" or "While You Were Away" banner
    let (_, remaining) = draw_banner(f, area, app);

    let alerts = &app.alert_engine.alerts;

    // Title bar
    let total_alerts = alerts.len();
    let unread = app.alert_engine.unread();
    let mut title_spans = vec![
        Span::styled(
            " Alerts ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} total ", total_alerts),
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
    // Key hints in title
    title_spans.push(Span::styled(
        "  \u{2190}\u{2192}:Pane  \u{2191}\u{2193}:Scroll  ",
        Style::default().fg(Color::Rgb(60, 80, 110)),
    ));

    let outer_block = Block::default()
        .title(Line::from(title_spans))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(12, 16, 28)));

    let inner = outer_block.inner(remaining);
    f.render_widget(outer_block, remaining);

    // Collect non-empty categories
    let active_cats = active_categories(alerts);

    if active_cats.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "  No alerts yet. Monitoring...",
            Style::default().fg(Color::Rgb(60, 80, 110)),
        )));
        f.render_widget(empty, inner);
        app.alert_pane_rects.clear();
        return;
    }

    // Clamp focused pane
    let focused = app.alert_focused_pane.min(active_cats.len().saturating_sub(1));
    app.alert_focused_pane = focused;

    // Split into rows of 3 panes each
    let num_cats = active_cats.len();
    let num_rows = (num_cats + 2) / 3;
    let row_constraints: Vec<Constraint> = (0..num_rows)
        .map(|_| Constraint::Ratio(1, num_rows as u32))
        .collect();

    let row_areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(row_constraints)
        .split(inner);

    // Cache pane rects for mouse hit-testing
    let mut pane_rects: Vec<(AlertCategory, Rect)> = Vec::with_capacity(num_cats);

    for (row_idx, chunk) in active_cats.chunks(3).enumerate() {
        let col_constraints: Vec<Constraint> = chunk.iter()
            .map(|_| Constraint::Ratio(1, chunk.len() as u32))
            .collect();

        let col_areas = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(col_constraints)
            .split(row_areas[row_idx]);

        for (col_idx, &cat) in chunk.iter().enumerate() {
            let pane_idx = row_idx * 3 + col_idx;
            let is_focused = pane_idx == focused;
            let scroll = app.alert_pane_scrolls[cat_ordinal(cat)];

            pane_rects.push((cat, col_areas[col_idx]));
            draw_category_pane(f, col_areas[col_idx], alerts, cat, is_focused, scroll);
        }
    }

    app.alert_pane_rects = pane_rects;
}

fn draw_banner(f: &mut Frame, area: Rect, app: &App) -> (u16, Rect) {
    if let Some(ref summary) = app.alert_engine.last_visit_summary {
        let h = 4u16;
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(h), Constraint::Min(5)])
            .split(area);

        let lines = vec![
            Line::from(vec![
                Span::styled(
                    " Since Your Last Visit ",
                    Style::default()
                        .fg(Color::Rgb(100, 200, 255))
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("(last seen: {}) ", summary.last_session_end),
                    Style::default().fg(Color::Rgb(150, 170, 200)),
                ),
                Span::styled(
                    "  Press any key to dismiss",
                    Style::default().fg(Color::Rgb(80, 100, 130)),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    format!("  {} alerts", summary.alert_count),
                    Style::default().fg(Color::Rgb(255, 160, 80)),
                ),
                Span::styled("  |  ", Style::default().fg(Color::Rgb(40, 55, 80))),
                Span::styled(
                    format!("{} connections", summary.connections),
                    Style::default().fg(Color::Rgb(100, 200, 160)),
                ),
                Span::styled("  |  ", Style::default().fg(Color::Rgb(40, 55, 80))),
                Span::styled(
                    format!("{} devices", summary.device_count),
                    Style::default().fg(Color::Rgb(180, 140, 255)),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    format!("  Down: {}  Up: {}", fmt_bytes(summary.bytes_down), fmt_bytes(summary.bytes_up)),
                    Style::default().fg(Color::Rgb(130, 170, 220)),
                ),
            ]),
        ];

        let banner = Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Rgb(30, 60, 100)))
                    .style(Style::default().bg(Color::Rgb(15, 22, 38))),
            );
        f.render_widget(banner, layout[0]);
        (h, layout[1])
    } else if let Some(ref summary) = app.alert_engine.idle_tracker.pending_summary {
        let event_lines = summary.events.len().min(3);
        let h = (3 + event_lines) as u16;
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(h), Constraint::Min(5)])
            .split(area);

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
    }
}

/// Draw a single category pane with its alerts.
fn draw_category_pane(
    f: &mut Frame,
    area: Rect,
    alerts: &[Alert],
    cat: AlertCategory,
    is_focused: bool,
    scroll_offset: usize,
) {
    let cat_alerts = alerts_for_category(alerts, cat);
    let unread = cat_alerts.iter().filter(|a| !a.read).count();

    // Build title
    let mut title_parts = vec![
        Span::styled(
            format!(" {} ", cat.label()),
            Style::default().fg(cat.color()).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("({})", cat_alerts.len()),
            Style::default().fg(Color::Rgb(100, 120, 150)),
        ),
    ];
    if unread > 0 {
        title_parts.push(Span::styled(
            format!(" {} new", unread),
            Style::default().fg(Color::Rgb(255, 100, 80)).add_modifier(Modifier::BOLD),
        ));
    }

    let border_color = if is_focused {
        Color::Rgb(100, 200, 255) // bright blue for focused
    } else {
        Color::Rgb(30, 45, 70) // dim for unfocused
    };

    let block = Block::default()
        .title(Line::from(title_parts))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(Color::Rgb(12, 16, 28)));

    let pane_inner = block.inner(area);
    f.render_widget(block, area);

    if cat_alerts.is_empty() {
        return;
    }

    // Build lines for all alerts
    let mut lines: Vec<Line> = Vec::new();

    for (i, alert) in cat_alerts.iter().enumerate() {
        let time_str = alert.timestamp.format("%H:%M:%S").to_string();
        let severity = alert.kind.severity();
        let sev_color = severity.color();
        let type_label = alert.kind.label();
        let desc = alert.kind.description();

        let read_dim = if alert.read { Modifier::DIM } else { Modifier::empty() };
        let unread_marker = if !alert.read { "\u{2022} " } else { "  " };

        // Highlight selected row in focused pane
        let is_selected = is_focused && i == scroll_offset;
        let bg = if is_selected {
            Style::default().bg(Color::Rgb(25, 45, 85))
        } else {
            Style::default()
        };

        lines.push(Line::from(vec![
            Span::styled(
                if is_selected { "\u{25b8} " } else { unread_marker },
                if is_selected {
                    Style::default().fg(Color::Rgb(100, 200, 255)).add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Rgb(255, 100, 80))
                },
            ),
            Span::styled(
                time_str,
                bg.fg(Color::Rgb(100, 110, 130)).add_modifier(read_dim),
            ),
            Span::styled(
                format!(" {} ", severity.label()),
                bg.fg(sev_color).add_modifier(Modifier::BOLD | read_dim),
            ),
            Span::styled(
                format!("[{}] ", type_label),
                bg.fg(Color::Rgb(180, 190, 220)).add_modifier(read_dim),
            ),
            Span::styled(
                desc,
                bg.fg(Color::Rgb(150, 160, 180)).add_modifier(read_dim),
            ),
        ]));
    }

    let visible = pane_inner.height as usize;
    let total = lines.len();

    // Viewport scrolling: keep selected row visible
    let viewport_start = if total <= visible {
        0
    } else {
        let half = visible / 2;
        if scroll_offset <= half {
            0
        } else if scroll_offset >= total.saturating_sub(half) {
            total.saturating_sub(visible)
        } else {
            scroll_offset.saturating_sub(half)
        }
    };

    let para = Paragraph::new(lines)
        .scroll((viewport_start as u16, 0))
        .wrap(Wrap { trim: false });

    f.render_widget(para, pane_inner);

    // Scrollbar if content overflows
    if total > visible {
        let sb_area = Rect {
            x: pane_inner.x + pane_inner.width.saturating_sub(1),
            y: pane_inner.y,
            width: 1,
            height: pane_inner.height,
        };
        let mut sb_state = ScrollbarState::new(total.saturating_sub(visible)).position(viewport_start);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(if is_focused {
                    Color::Rgb(60, 120, 180)
                } else {
                    Color::Rgb(30, 50, 80)
                })),
            sb_area,
            &mut sb_state,
        );
    }
}
