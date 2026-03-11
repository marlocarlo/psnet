//! Networks tab UI — shows devices on non-primary networks
//! (VPNs, Docker, WSL, Hyper-V, secondary adapters).
//! Bluetooth devices are displayed last in a collapsible section.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;
use crate::types::NetworkCategory;

/// Represents a virtual row in the networks display.
#[derive(Clone)]
pub enum NetworksRow<'a> {
    Device {
        net_name: &'a str,
        category: &'a NetworkCategory,
        device: &'a crate::types::LanDevice,
    },
    BluetoothHeader {
        count: usize,
        expanded: bool,
    },
}

/// Build the virtual row list: non-BT devices (sorted), then BT header, then BT devices if expanded.
pub fn build_display_rows<'a>(app: &'a App) -> Vec<NetworksRow<'a>> {
    let scanner = &app.networks_scanner;

    let mut main_flat: Vec<(&str, &NetworkCategory, &crate::types::LanDevice)> = Vec::new();
    let mut bt_flat: Vec<(&str, &NetworkCategory, &crate::types::LanDevice)> = Vec::new();

    for net in &scanner.networks {
        for dev in &net.devices {
            if net.category == NetworkCategory::Bluetooth {
                bt_flat.push((&net.name, &net.category, dev));
            } else {
                main_flat.push((&net.name, &net.category, dev));
            }
        }
    }

    // Sort both lists
    let sort_col = app.networks_sort_column;
    let sort_asc = app.networks_sort_ascending;
    let sorter = |a: &(&str, &NetworkCategory, &crate::types::LanDevice),
                  b: &(&str, &NetworkCategory, &crate::types::LanDevice)| {
        let ord = match sort_col {
            0 => a.0.cmp(b.0),
            1 => category_label(a.1).cmp(&category_label(b.1)),
            2 => b.2.is_online.cmp(&a.2.is_online),
            3 => a.2.ip.to_string().cmp(&b.2.ip.to_string()),
            4 => a.2.hostname.as_deref().unwrap_or("~").cmp(&b.2.hostname.as_deref().unwrap_or("~")),
            5 => a.2.mac.cmp(&b.2.mac),
            6 => a.2.vendor.as_deref().unwrap_or("~").cmp(&b.2.vendor.as_deref().unwrap_or("~")),
            7 => a.2.open_ports.cmp(&b.2.open_ports),
            _ => std::cmp::Ordering::Equal,
        };
        if sort_asc { ord.reverse() } else { ord }
    };
    main_flat.sort_by(sorter);
    bt_flat.sort_by(sorter);

    let mut rows = Vec::new();

    // Main (non-BT) devices
    for (net_name, category, device) in &main_flat {
        rows.push(NetworksRow::Device {
            net_name,
            category,
            device,
        });
    }

    // Bluetooth section
    let bt_count = bt_flat.len();
    if bt_count > 0 {
        rows.push(NetworksRow::BluetoothHeader {
            count: bt_count,
            expanded: app.bluetooth_expanded,
        });

        if app.bluetooth_expanded {
            for (net_name, category, device) in &bt_flat {
                rows.push(NetworksRow::Device {
                    net_name,
                    category,
                    device,
                });
            }
        }
    }

    rows
}

pub fn draw_networks(f: &mut Frame, area: Rect, app: &App) {
    let scanner = &app.networks_scanner;
    let display_rows = build_display_rows(app);

    let total = display_rows.len();
    let visible_height = area.height.saturating_sub(5) as usize;
    let selected = if total > 0 { app.networks_scroll.min(total - 1) } else { 0 };

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
        if app.networks_sort_column == col {
            if app.networks_sort_ascending { " \u{25b2}" } else { " \u{25bc}" }
        } else { "" }
    };

    let header = Row::new(vec![
        Cell::from(Span::styled(format!("Network{}", si(0)), hdr_style)),
        Cell::from(Span::styled(format!("Type{}", si(1)), hdr_style)),
        Cell::from(Span::styled(format!("Status{}", si(2)), hdr_style)),
        Cell::from(Span::styled(format!("IP Address{}", si(3)), hdr_style)),
        Cell::from(Span::styled(format!("Hostname{}", si(4)), hdr_style)),
        Cell::from(Span::styled(format!("MAC{}", si(5)), hdr_style)),
        Cell::from(Span::styled(format!("Vendor{}", si(6)), hdr_style)),
        Cell::from(Span::styled(format!("Ports{}", si(7)), hdr_style)),
    ])
    .height(1)
    .style(Style::default().bg(Color::Rgb(18, 25, 42)));

    let rows: Vec<Row> = display_rows
        .iter()
        .enumerate()
        .skip(viewport_start)
        .take(visible_height)
        .map(|(idx, row)| {
            let is_selected = idx == selected;
            match row {
                NetworksRow::BluetoothHeader { count, expanded } => {
                    let arrow = if *expanded { "\u{25bc}" } else { "\u{25b6}" };
                    let label = format!("{} Bluetooth ({} devices)", arrow, count);
                    let bg = if is_selected {
                        Color::Rgb(25, 45, 85)
                    } else {
                        Color::Rgb(16, 22, 38)
                    };
                    Row::new(vec![
                        Cell::from(Span::styled(
                            label,
                            Style::default()
                                .fg(Color::Rgb(100, 200, 240))
                                .add_modifier(Modifier::BOLD),
                        )),
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(Span::styled(
                            if *expanded { "b:collapse" } else { "b:expand / Enter" }.to_string(),
                            Style::default().fg(Color::Rgb(60, 80, 110)),
                        )),
                        Cell::from(""),
                        Cell::from(""),
                        Cell::from(""),
                    ])
                    .style(Style::default().bg(bg))
                }
                NetworksRow::Device { net_name, category, device } => {
                    let cat_label = category_label(category);
                    let cat_color = category_color(category);

                    let (status_icon, status_color) = if device.is_online {
                        ("\u{25cf} ONLINE", Color::Rgb(80, 200, 120))
                    } else {
                        ("\u{25cb} OFFLINE", Color::Rgb(100, 100, 120))
                    };

                    let hostname_display = device.hostname.as_deref().unwrap_or("\u{2014}");
                    let hostname_color = if device.hostname.is_some() {
                        Color::Rgb(130, 200, 180)
                    } else {
                        Color::Rgb(60, 65, 80)
                    };

                    let vendor = device.vendor.as_deref().unwrap_or("Unknown");

                    let row_bg = if is_selected {
                        Color::Rgb(25, 45, 85)
                    } else if device.is_online {
                        Color::Rgb(14, 18, 30)
                    } else {
                        Color::Rgb(10, 12, 22)
                    };

                    Row::new(vec![
                        Cell::from(Span::styled(
                            (*net_name).to_string(),
                            Style::default().fg(Color::Rgb(140, 160, 200)),
                        )),
                        Cell::from(Span::styled(
                            cat_label.to_string(),
                            Style::default().fg(cat_color).add_modifier(Modifier::BOLD),
                        )),
                        Cell::from(Span::styled(
                            status_icon,
                            Style::default().fg(status_color).add_modifier(Modifier::BOLD),
                        )),
                        Cell::from(Span::styled(
                            device.ip.to_string(),
                            Style::default().fg(Color::Rgb(100, 180, 255)),
                        )),
                        Cell::from(Span::styled(
                            hostname_display,
                            Style::default().fg(hostname_color),
                        )),
                        Cell::from(Span::styled(
                            if device.mac.is_empty() { "\u{2014}".to_string() } else { device.mac.clone() },
                            Style::default().fg(Color::Rgb(150, 160, 180)),
                        )),
                        Cell::from(Span::styled(
                            vendor.to_string(),
                            Style::default().fg(Color::Rgb(180, 170, 140)),
                        )),
                        Cell::from(Span::styled(
                            if device.open_ports.is_empty() { "\u{2014}".to_string() } else { device.open_ports.clone() },
                            Style::default().fg(if device.open_ports.is_empty() {
                                Color::Rgb(60, 70, 90)
                            } else {
                                Color::Rgb(180, 200, 120)
                            }),
                        )),
                    ])
                    .style(Style::default().bg(row_bg))
                }
            }
        })
        .collect();

    // Title — count all devices (including collapsed BT)
    let all_device_count: usize = scanner.networks.iter().map(|n| n.devices.len()).sum();
    let net_count = scanner.networks.len();
    let scanning_str = if scanner.is_scanning() {
        " \u{1f50d} Scanning...".to_string()
    } else {
        String::new()
    };

    let mut title_spans = vec![
        Span::styled(
            " Networks ",
            Style::default().fg(Color::Rgb(160, 180, 220)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} networks, {} devices ", net_count, all_device_count),
            Style::default().fg(Color::Rgb(100, 120, 150)),
        ),
    ];
    if !scanning_str.is_empty() {
        title_spans.push(Span::styled(
            scanning_str,
            Style::default().fg(Color::Rgb(80, 200, 255)).add_modifier(Modifier::BOLD),
        ));
    }

    let hint = Line::from(Span::styled(
        " s:scan  b:bluetooth  Enter:details",
        Style::default().fg(Color::Rgb(55, 70, 100)),
    ));

    let table = Table::new(
        rows,
        [
            Constraint::Length(24),  // Network
            Constraint::Length(10),  // Type
            Constraint::Length(10),  // Status
            Constraint::Length(18),  // IP Address
            Constraint::Min(14),     // Hostname
            Constraint::Length(18),  // MAC
            Constraint::Length(20),  // Vendor
            Constraint::Length(22),  // Ports
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Line::from(title_spans))
            .title_bottom(hint)
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

fn category_label(cat: &NetworkCategory) -> &'static str {
    match cat {
        NetworkCategory::Vpn => "VPN",
        NetworkCategory::Docker => "Docker",
        NetworkCategory::Wsl => "WSL",
        NetworkCategory::HyperV => "Hyper-V",
        NetworkCategory::Virtual => "VM",
        NetworkCategory::Secondary => "LAN",
        NetworkCategory::Bluetooth => "Bluetooth",
        NetworkCategory::MeshVpn => "Mesh VPN",
        NetworkCategory::Hotspot => "Hotspot",
        NetworkCategory::Tunnel => "Tunnel",
    }
}

fn category_color(cat: &NetworkCategory) -> Color {
    match cat {
        NetworkCategory::Vpn => Color::Rgb(100, 220, 180),
        NetworkCategory::Docker => Color::Rgb(80, 160, 255),
        NetworkCategory::Wsl => Color::Rgb(255, 160, 60),
        NetworkCategory::HyperV => Color::Rgb(180, 130, 255),
        NetworkCategory::Virtual => Color::Rgb(200, 180, 100),
        NetworkCategory::Secondary => Color::Rgb(140, 180, 140),
        NetworkCategory::Bluetooth => Color::Rgb(100, 200, 240),
        NetworkCategory::MeshVpn => Color::Rgb(80, 220, 120),
        NetworkCategory::Hotspot => Color::Rgb(255, 180, 60),
        NetworkCategory::Tunnel => Color::Rgb(180, 120, 255),
    }
}
