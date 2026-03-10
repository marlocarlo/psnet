//! Firewall tab UI — app-centric block/allow management.
//!
//! Shows apps that are currently making network connections (or were previously
//! blocked), with a clear BLOCKED/ALLOWED status and Enter to toggle.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;
use crate::types::{FirewallAppAction, FirewallMode};

pub fn draw_firewall(f: &mut Frame, area: Rect, app: &App) {
    let fw_area = area; // Save for menu overlay
    let apps = app.firewall_app_list_filtered();
    let blocked_count = apps.iter().filter(|(_, b, _)| *b).count();

    let fw = &app.firewall_manager;
    let filter_info = if fw.filter_text.is_empty() {
        String::new()
    } else {
        format!(" [filter: {}]", fw.filter_text)
    };

    let mut title_spans = vec![
        Span::styled(
            " Firewall ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} apps ", apps.len()),
            Style::default().fg(Color::Rgb(100, 120, 150)),
        ),
        Span::styled(
            format!(" {} blocked ", blocked_count),
            Style::default()
                .fg(if blocked_count > 0 { Color::Rgb(255, 120, 80) } else { Color::Rgb(70, 90, 120) }),
        ),
    ];
    if !filter_info.is_empty() {
        title_spans.push(Span::styled(filter_info, Style::default().fg(Color::Yellow)));
    }

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
            Constraint::Length(3),  // Status strip
            Constraint::Min(6),     // App list
        ])
        .split(inner);

    draw_firewall_status(f, chunks[0], app);
    draw_firewall_apps(f, chunks[1], app, &apps);

    // Floating action menu overlay
    if app.firewall_menu.is_some() {
        draw_firewall_menu(f, fw_area, app);
    }
}

fn draw_firewall_status(f: &mut Frame, area: Rect, app: &App) {
    let fw = &app.firewall_manager;

    let status_str = if fw.enabled { "ACTIVE" } else { "DISABLED" };
    let status_color = if fw.enabled { Color::Rgb(80, 200, 120) } else { Color::Rgb(255, 80, 80) };

    let mode_color = match fw.mode {
        FirewallMode::Normal => Color::Rgb(80, 180, 255),
        FirewallMode::AskToConnect => Color::Rgb(255, 200, 60),
        FirewallMode::Lockdown => Color::Rgb(255, 80, 80),
    };

    let pending_str = if fw.mode == FirewallMode::AskToConnect && !fw.pending_apps.is_empty() {
        format!("  |  {} pending: {}", fw.pending_apps.len(),
            fw.pending_apps.iter().take(3).cloned().collect::<Vec<_>>().join(", "))
    } else {
        String::new()
    };

    let line = Line::from(vec![
        Span::styled("  Shield: ", Style::default().fg(Color::Rgb(120, 140, 170))),
        Span::styled(status_str, Style::default().fg(status_color).add_modifier(Modifier::BOLD)),
        Span::styled("  |  Mode: ", Style::default().fg(Color::Rgb(80, 100, 130))),
        Span::styled(fw.mode.label(), Style::default().fg(mode_color).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("  |  {} blocked by psnet", fw.blocked_apps.len()),
            Style::default().fg(Color::Rgb(90, 110, 140)),
        ),
        Span::styled(pending_str, Style::default().fg(Color::Rgb(255, 200, 60))),
    ]);

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    f.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_firewall_apps(
    f: &mut Frame,
    area: Rect,
    app: &App,
    apps: &[(String, bool, usize)],
) {
    let total = apps.len();
    let visible_height = area.height.saturating_sub(5) as usize;
    let selected = if total > 0 {
        app.firewall_manager.scroll_offset.min(total - 1)
    } else {
        0
    };

    // Build display items — insert separator between active and inactive groups
    enum DisplayItem<'a> {
        App(usize, &'a (String, bool, usize)), // original index, app data
        Separator(&'static str),
    }

    let display_items: Vec<DisplayItem> = if total == 0 {
        Vec::new()
    } else {
        let active_count = apps.iter().filter(|(_, _, c)| *c > 0).count();
        let inactive_count = apps.iter().filter(|(_, _, c)| *c == 0).count();
        let mut items = Vec::new();
        if active_count > 0 {
            for (idx, app_entry) in apps.iter().enumerate().filter(|(_, (_, _, c))| *c > 0) {
                items.push(DisplayItem::App(idx, app_entry));
            }
        }
        if inactive_count > 0 && active_count > 0 {
            items.push(DisplayItem::Separator("─── Inactive / Not Currently Connected ───"));
        }
        for (idx, app_entry) in apps.iter().enumerate().filter(|(_, (_, _, c))| *c == 0) {
            items.push(DisplayItem::App(idx, app_entry));
        }
        items
    };
    let display_total = display_items.len();

    // Viewport follows selection — find display index of selected app for centering
    let selected_display_idx = display_items.iter().position(|item| {
        matches!(item, DisplayItem::App(idx, _) if *idx == selected)
    }).unwrap_or(0);

    let viewport_start = if display_total <= visible_height {
        0
    } else {
        let half = visible_height / 2;
        if selected_display_idx <= half {
            0
        } else if selected_display_idx >= display_total.saturating_sub(half) {
            display_total.saturating_sub(visible_height)
        } else {
            selected_display_idx.saturating_sub(half)
        }
    };

    let hdr_style = Style::default()
        .fg(Color::Rgb(160, 180, 220))
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from(Span::styled("Status", hdr_style)),
        Cell::from(Span::styled("Application", hdr_style)),
        Cell::from(Span::styled("Connections", hdr_style)),
    ])
    .height(1)
    .style(Style::default().bg(Color::Rgb(18, 25, 42)));

    let rows: Vec<Row> = if display_total == 0 {
        // Empty state — helpful message
        vec![Row::new(vec![
            Cell::from(""),
            Cell::from(Span::styled(
                "  No apps detected yet. Apps appear here when they make network connections.",
                Style::default().fg(Color::Rgb(80, 100, 140)),
            )),
            Cell::from(""),
        ])
        .style(Style::default().bg(Color::Rgb(12, 16, 28)))]
    } else {
        display_items
            .iter()
            .enumerate()
            .skip(viewport_start)
            .take(visible_height)
            .map(|(_display_idx, item)| match item {
                DisplayItem::Separator(label) => Row::new(vec![
                    Cell::from(""),
                    Cell::from(Span::styled(
                        *label,
                        Style::default().fg(Color::Rgb(60, 80, 110)),
                    )),
                    Cell::from(""),
                ])
                .style(Style::default().bg(Color::Rgb(8, 10, 20))),

                DisplayItem::App(idx, (name, is_blocked, conn_count)) => {
                    let is_selected = *idx == selected;

                    let action = app.firewall_manager.get_app_action(name);
                    let (status_str, status_color) = match action {
                        Some(FirewallAppAction::Deny) => ("DENY", Color::Rgb(255, 80, 80)),
                        Some(FirewallAppAction::Drop) => ("DROP", Color::Rgb(255, 140, 40)),
                        Some(FirewallAppAction::Allow) => ("ALLOW", Color::Rgb(80, 200, 255)),
                        None if *is_blocked => ("BLOCKED", Color::Rgb(255, 80, 80)),
                        None => ("ALLOWED", Color::Rgb(80, 200, 120)),
                    };

                    let prefix = if is_selected { "▶ " } else { "  " };
                    let display_name = format!("{}{}", prefix, truncate_str(name, 38));

                    let conn_str = if *conn_count > 0 {
                        conn_count.to_string()
                    } else {
                        "-".to_string()
                    };

                    let row_bg = if is_selected {
                        Color::Rgb(25, 45, 85)
                    } else if *is_blocked {
                        Color::Rgb(22, 10, 10)
                    } else {
                        Color::Rgb(12, 16, 28)
                    };

                    Row::new(vec![
                        Cell::from(Span::styled(
                            status_str,
                            Style::default()
                                .fg(status_color)
                                .add_modifier(Modifier::BOLD),
                        )),
                        Cell::from(Span::styled(
                            display_name,
                            Style::default().fg(if *is_blocked {
                                Color::Rgb(200, 130, 130)
                            } else {
                                Color::Rgb(160, 200, 160)
                            }),
                        )),
                        Cell::from(Span::styled(
                            conn_str,
                            Style::default().fg(Color::Rgb(120, 150, 190)),
                        )),
                    ])
                    .style(Style::default().bg(row_bg))
                }
            })
            .collect()
    };

    // Bottom hint — context-aware based on selected app
    let hint_line = if let Some((name, _, _)) = apps.get(selected) {
        Line::from(vec![
            Span::styled(
                " Enter ",
                Style::default()
                    .fg(Color::Rgb(255, 200, 80))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("Action ", Style::default().fg(Color::Rgb(140, 170, 210))),
            Span::styled(truncate_str(name, 24), Style::default().fg(Color::Rgb(160, 180, 220))),
            Span::styled(
                "  |  f: filter  |  r: refresh  |  x: reset all",
                Style::default().fg(Color::Rgb(55, 70, 100)),
            ),
        ])
    } else {
        Line::from(Span::styled(
            "  Apps will appear here when they make network connections",
            Style::default().fg(Color::Rgb(60, 80, 110)),
        ))
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(9),   // Status
            Constraint::Min(24),     // Application
            Constraint::Length(12),  // Connections
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title_bottom(hint_line)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
            .style(Style::default().bg(Color::Rgb(12, 16, 28))),
    );

    f.render_widget(table, area);

    // Scrollbar
    if display_total > visible_height {
        let sb_area = Rect {
            x: area.x + area.width - 1,
            y: area.y + 2,
            width: 1,
            height: area.height.saturating_sub(3),
        };
        let mut sb_state =
            ScrollbarState::new(display_total.saturating_sub(visible_height)).position(viewport_start);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(Color::Rgb(40, 70, 120))),
            sb_area,
            &mut sb_state,
        );
    }
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    } else {
        s.to_string()
    }
}

fn draw_firewall_menu(f: &mut Frame, parent_area: Rect, app: &App) {
    let Some(ref menu) = app.firewall_menu else { return };

    // Compact floating box — centered in the firewall area
    let menu_w: u16 = 28;
    let menu_h: u16 = 7; // border + 3 items + title + border
    let x = parent_area.x + parent_area.width.saturating_sub(menu_w) / 2;
    let y = parent_area.y + parent_area.height.saturating_sub(menu_h) / 2;
    let area = Rect::new(x, y, menu_w.min(parent_area.width), menu_h.min(parent_area.height));

    f.render_widget(Clear, area);

    let title = truncate_str(&menu.app_name, 22);
    let block = Block::default()
        .title(Line::from(Span::styled(
            format!(" {} ", title),
            Style::default().fg(Color::Rgb(200, 210, 230)).add_modifier(Modifier::BOLD),
        )))
        .title_bottom(Line::from(Span::styled(
            " Esc:cancel ",
            Style::default().fg(Color::Rgb(55, 70, 100)),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(80, 130, 200)))
        .style(Style::default().bg(Color::Rgb(16, 22, 40)));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let options: [(usize, &str, Color); 3] = [
        (0, " Allow ", Color::Rgb(80, 200, 120)),
        (1, " Deny  ", Color::Rgb(255, 80, 80)),
        (2, " Drop  ", Color::Rgb(255, 140, 40)),
    ];

    // Current action marker
    let current = app.firewall_manager.get_app_action(&menu.app_name);

    for (i, (idx, label, color)) in options.iter().enumerate() {
        if i as u16 >= inner.height { break; }
        let row_area = Rect::new(inner.x, inner.y + i as u16, inner.width, 1);
        let is_sel = menu.selected == *idx;
        let is_current = match (current, idx) {
            (Some(FirewallAppAction::Allow), 0) => true,
            (Some(FirewallAppAction::Deny), 1) => true,
            (Some(FirewallAppAction::Drop), 2) => true,
            _ => false,
        };

        let prefix = if is_sel { "▶ " } else { "  " };
        let suffix = if is_current { " ●" } else { "" };

        let bg = if is_sel {
            Color::Rgb(30, 55, 100)
        } else {
            Color::Rgb(16, 22, 40)
        };

        let line = Line::from(vec![
            Span::styled(prefix, Style::default().fg(Color::Rgb(255, 200, 80))),
            Span::styled(*label, Style::default().fg(*color).add_modifier(Modifier::BOLD)),
            Span::styled(suffix, Style::default().fg(Color::Rgb(80, 200, 120))),
        ]);
        f.render_widget(
            Paragraph::new(line).style(Style::default().bg(bg)),
            row_area,
        );
    }
}
