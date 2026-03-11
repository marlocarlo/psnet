//! LAN Devices tab UI — network scanner results display.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;
use crate::utils::format_bytes;

fn format_speed(bps: f64) -> String {
    if bps < 1.0 {
        "—".to_string()
    } else {
        format!("{}/s", format_bytes(bps as u64))
    }
}

pub fn draw_devices(f: &mut Frame, area: Rect, app: &App) {
    let scanner = &app.network_scanner;
    let mut devices: Vec<&crate::types::LanDevice> = scanner.devices.iter().collect();
    // Sort by selected column
    let sort_col = app.device_sort_column;
    let sort_asc = app.device_sort_ascending;
    devices.sort_by(|a, b| {
        let ord = match sort_col {
            0 => b.is_online.cmp(&a.is_online),     // Status: online first
            1 => a.ip.to_string().cmp(&b.ip.to_string()), // IP
            2 => a.hostname.as_deref().unwrap_or("~").cmp(&b.hostname.as_deref().unwrap_or("~")),
            3 => a.mac.cmp(&b.mac),
            4 => a.vendor.as_deref().unwrap_or("~").cmp(&b.vendor.as_deref().unwrap_or("~")),
            5 => a.open_ports.cmp(&b.open_ports),    // Ports
            6 => a.first_seen.cmp(&b.first_seen),
            7 => b.last_seen.cmp(&a.last_seen),      // Last seen: most recent first
            8 => a.speed_received.partial_cmp(&b.speed_received).unwrap_or(std::cmp::Ordering::Equal),
            9 => a.speed_sent.partial_cmp(&b.speed_sent).unwrap_or(std::cmp::Ordering::Equal),
            10 => a.discovery_info.cmp(&b.discovery_info),
            _ => std::cmp::Ordering::Equal,
        };
        if sort_asc { ord.reverse() } else { ord }
    });
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

    let si = |col: usize| -> &str {
        if app.device_sort_column == col {
            if app.device_sort_ascending { " \u{25b2}" } else { " \u{25bc}" }
        } else { "" }
    };

    let header = Row::new(vec![
        Cell::from(Span::styled(format!("Status{}", si(0)), hdr_style)),
        Cell::from(Span::styled(format!("IP Address{}", si(1)), hdr_style)),
        Cell::from(Span::styled(format!("Hostname{}", si(2)), hdr_style)),
        Cell::from(Span::styled(format!("MAC{}", si(3)), hdr_style)),
        Cell::from(Span::styled(format!("Vendor{}", si(4)), hdr_style)),
        Cell::from(Span::styled(format!("Ports{}", si(5)), hdr_style)),
        Cell::from(Span::styled(format!("First{}", si(6)), hdr_style)),
        Cell::from(Span::styled(format!("Last{}", si(7)), hdr_style)),
        Cell::from(Span::styled(format!("↓ Recv{}", si(8)), hdr_style)),
        Cell::from(Span::styled(format!("↑ Sent{}", si(9)), hdr_style)),
        Cell::from(Span::styled(format!("Details{}", si(10)), hdr_style)),
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

            let hostname_display = device.hostname.as_deref().unwrap_or("—");
            let hostname_color = if device.hostname.is_some() {
                Color::Rgb(130, 200, 180)
            } else {
                Color::Rgb(60, 65, 80)
            };

            let vendor = device.custom_name.as_deref()
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
                    hostname_display,
                    Style::default().fg(hostname_color),
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
                    if device.open_ports.is_empty() {
                        "—".to_string()
                    } else {
                        device.open_ports.clone()
                    },
                    Style::default().fg(if device.open_ports.is_empty() {
                        Color::Rgb(60, 70, 90)
                    } else {
                        Color::Rgb(180, 200, 120)
                    }),
                )),
                Cell::from(Span::styled(
                    first_seen,
                    Style::default().fg(Color::Rgb(90, 100, 120)),
                )),
                Cell::from(Span::styled(
                    last_seen,
                    Style::default().fg(Color::Rgb(90, 100, 120)),
                )),
                Cell::from(Span::styled(
                    if device.bytes_received > 0 {
                        format!("{} ({})", format_bytes(device.bytes_received), format_speed(device.speed_received))
                    } else {
                        "—".to_string()
                    },
                    Style::default().fg(if device.speed_received > 0.0 {
                        Color::Rgb(80, 200, 255)
                    } else {
                        Color::Rgb(60, 70, 90)
                    }),
                )),
                Cell::from(Span::styled(
                    if device.bytes_sent > 0 {
                        format!("{} ({})", format_bytes(device.bytes_sent), format_speed(device.speed_sent))
                    } else {
                        "—".to_string()
                    },
                    Style::default().fg(if device.speed_sent > 0.0 {
                        Color::Rgb(255, 180, 100)
                    } else {
                        Color::Rgb(60, 70, 90)
                    }),
                )),
                Cell::from(Span::styled(
                    if device.discovery_info.is_empty() {
                        "—".to_string()
                    } else {
                        device.discovery_info.clone()
                    },
                    Style::default().fg(if device.discovery_info.is_empty() {
                        Color::Rgb(60, 70, 90)
                    } else {
                        Color::Rgb(140, 160, 130)
                    }),
                )),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    // Title
    let scanning_str = if scanner.is_scanning() {
        let (probed, total) = scanner.scan_progress();
        let phase = scanner.scan_phase();
        match phase {
            crate::network::scanner::SCAN_PHASE_ARP => {
                if total > 0 {
                    format!(" 🔍 ARP {}/{} IPs", probed, total)
                } else {
                    " 🔍 Starting...".to_string()
                }
            }
            crate::network::scanner::SCAN_PHASE_DNS => {
                if total > 0 {
                    format!(" 🔍 DNS {}/{} hosts", probed, total)
                } else {
                    " 🔍 Resolving hostnames...".to_string()
                }
            }
            _ => " 🔍 Scanning...".to_string(),
        }
    } else {
        String::new()
    };
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
            Constraint::Length(14),  // Hostname
            Constraint::Length(18),  // MAC Address
            Constraint::Length(20),  // Vendor (wider to avoid truncation)
            Constraint::Length(22),  // Ports
            Constraint::Length(9),   // First Seen
            Constraint::Length(9),   // Last Seen
            Constraint::Length(18),  // Recv
            Constraint::Length(18),  // Sent
            Constraint::Min(20),    // Details
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
