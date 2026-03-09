//! LAN Devices tab UI — network scanner results display.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;

pub fn draw_devices(f: &mut Frame, area: Rect, app: &App) {
    let scanner = &app.network_scanner;
    let devices = &scanner.devices;
    let total = devices.len();
    let online = scanner.online_count();

    let visible_height = area.height.saturating_sub(5) as usize;
    let selected = if total > 0 { app.device_scroll.min(total - 1) } else { 0 };

    // Viewport follows selection (centered)
    let viewport_start = if total <= visible_height {
        0
    } else {
        let half = visible_height / 2;
        if selected <= half {
            0
        } else if selected >= total.saturating_sub(half) {
            total.saturating_sub(visible_height)
        } else {
            selected.saturating_sub(half)
        }
    };

    let hdr_style = Style::default()
        .fg(Color::Rgb(160, 180, 220))
        .add_modifier(Modifier::BOLD);

    let header = Row::new(vec![
        Cell::from(Span::styled("Status", hdr_style)),
        Cell::from(Span::styled("IP Address", hdr_style)),
        Cell::from(Span::styled("MAC Address", hdr_style)),
        Cell::from(Span::styled("Name / Vendor", hdr_style)),
        Cell::from(Span::styled("First Seen", hdr_style)),
        Cell::from(Span::styled("Last Seen", hdr_style)),
    ])
    .height(1)
    .style(Style::default().bg(Color::Rgb(18, 25, 42)));

    let rows: Vec<Row> = devices
        .iter()
        .enumerate()
        .skip(viewport_start)
        .take(visible_height)
        .map(|(idx, device)| {
            let is_selected = idx == selected;
            let (status_icon, status_color) = if device.is_online {
                ("● ONLINE", Color::Rgb(80, 200, 120))
            } else {
                ("○ OFFLINE", Color::Rgb(100, 100, 120))
            };

            let vendor = device.custom_name.as_deref()
                .or(device.hostname.as_deref())
                .or(device.vendor.as_deref())
                .unwrap_or("Unknown");
            let vendor_color = if device.custom_name.is_some() {
                Color::Rgb(255, 220, 100)  // gold for custom labels
            } else {
                Color::Rgb(180, 170, 140)  // default
            };
            let first_seen = device.first_seen.format("%H:%M:%S").to_string();
            let last_seen = device.last_seen.format("%H:%M:%S").to_string();

            let is_gateway = scanner.gateway
                .map(|gw| device.ip == std::net::IpAddr::V4(gw))
                .unwrap_or(false);

            let ip_display = if is_gateway {
                format!("{} (gateway)", device.ip)
            } else {
                device.ip.to_string()
            };

            let row_bg = if is_selected {
                Color::Rgb(25, 45, 85)
            } else if device.is_online {
                Color::Rgb(14, 18, 30)
            } else {
                Color::Rgb(10, 12, 22)
            };

            Row::new(vec![
                Cell::from(Span::styled(
                    status_icon,
                    Style::default().fg(status_color).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    ip_display,
                    Style::default().fg(if is_gateway {
                        Color::Rgb(255, 200, 80)
                    } else {
                        Color::Rgb(100, 180, 255)
                    }),
                )),
                Cell::from(Span::styled(
                    device.mac.clone(),
                    Style::default().fg(Color::Rgb(150, 160, 180)),
                )),
                Cell::from(Span::styled(
                    vendor.to_string(),
                    Style::default().fg(vendor_color),
                )),
                Cell::from(Span::styled(
                    first_seen,
                    Style::default().fg(Color::Rgb(90, 100, 120)),
                )),
                Cell::from(Span::styled(
                    last_seen,
                    Style::default().fg(Color::Rgb(90, 100, 120)),
                )),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    // Title
    let scanning_str = if scanner.is_scanning() { " 🔍 Scanning..." } else { "" };
    let local_ip_str = scanner.local_ip
        .map(|ip| format!("  Local: {}", ip))
        .unwrap_or_default();

    let mut title_spans = vec![
        Span::styled(
            " Devices ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {}/{} online ", online, total),
            Style::default().fg(Color::Rgb(100, 120, 150)),
        ),
    ];
    if !scanning_str.is_empty() {
        title_spans.push(Span::styled(
            scanning_str,
            Style::default().fg(Color::Rgb(80, 200, 255)).add_modifier(Modifier::BOLD),
        ));
    }
    if !local_ip_str.is_empty() {
        title_spans.push(Span::styled(
            local_ip_str,
            Style::default().fg(Color::Rgb(80, 160, 200)),
        ));
    }

    let rename_hint = if app.renaming_device.is_some() {
        Line::from(vec![
            Span::styled(" Rename: ", Style::default().fg(Color::Rgb(255, 200, 80)).add_modifier(ratatui::style::Modifier::BOLD)),
            Span::styled(app.device_rename_text.clone(), Style::default().fg(Color::White)),
            Span::styled("█", Style::default().fg(Color::Rgb(255, 200, 80))),
            Span::styled("  Enter:confirm  Esc:cancel", Style::default().fg(Color::Rgb(55, 70, 100))),
        ])
    } else {
        let selected_name = if !app.network_scanner.devices.is_empty() {
            let idx = app.device_scroll.min(app.network_scanner.devices.len() - 1);
            app.network_scanner.devices.get(idx)
                .map(|d| {
                    let name = d.custom_name.as_deref().or(d.hostname.as_deref());
                    match name {
                        Some(n) => format!(" r:rename \"{}\"", n),
                        None => " r:rename  s:scan".to_string(),
                    }
                })
                .unwrap_or_else(|| " r:rename  s:scan".to_string())
        } else {
            " s:scan".to_string()
        };
        Line::from(Span::styled(selected_name, Style::default().fg(Color::Rgb(55, 70, 100))))
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),  // Status
            Constraint::Length(22),  // IP Address
            Constraint::Length(18),  // MAC Address
            Constraint::Min(16),     // Vendor
            Constraint::Length(10),  // First Seen
            Constraint::Length(10),  // Last Seen
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Line::from(title_spans))
            .title_bottom(rename_hint)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
            .style(Style::default().bg(Color::Rgb(12, 16, 28))),
    );

    f.render_widget(table, area);

    // Scrollbar
    if total > visible_height {
        let sb_area = Rect {
            x: area.x + area.width - 1,
            y: area.y + 2,
            width: 1,
            height: area.height.saturating_sub(3),
        };
        let mut sb_state = ScrollbarState::new(total.saturating_sub(visible_height)).position(viewport_start);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(Color::Rgb(40, 70, 120))),
            sb_area,
            &mut sb_state,
        );
    }
}
