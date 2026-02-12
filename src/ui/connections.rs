use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table,
};
use ratatui::Frame;

use crate::app::App;
use crate::network::dns::port_service_name;
use crate::types::{BottomTab, TcpState};

pub fn draw_connections(f: &mut Frame, area: Rect, app: &App) {
    let filtered = app.filtered_connections();
    let total = filtered.len();

    let sort_ind = |col: usize| -> &str {
        if app.sort_column == col {
            if app.sort_ascending { " \u{25B2}" } else { " \u{25BC}" }
        } else {
            ""
        }
    };

    let hdr_style = Style::default()
        .fg(Color::Rgb(160, 180, 220))
        .add_modifier(Modifier::BOLD);

    // ── Redesigned columns: Process | Remote Host | Service | State | Local ──
    let header = Row::new(vec![
        Cell::from(Span::styled(format!("Process{}", sort_ind(6)), hdr_style)),
        Cell::from(Span::styled(format!("Remote Host{}", sort_ind(3)), hdr_style)),
        Cell::from(Span::styled(format!("Service{}", sort_ind(4)), hdr_style)),
        Cell::from(Span::styled(format!("State{}", sort_ind(5)), hdr_style)),
        Cell::from(Span::styled(format!("Local{}", sort_ind(2)), hdr_style)),
    ])
    .height(1)
    .style(Style::default().bg(Color::Rgb(18, 25, 42)));

    let visible_height = area.height.saturating_sub(5) as usize;
    let scroll = app.conn_scroll.min(total.saturating_sub(visible_height));

    let rows: Vec<Row> = filtered
        .iter()
        .skip(scroll)
        .take(visible_height)
        .map(|conn| {
            // ── Process name ──
            let proc_name = &conn.process_name;
            let proc_display = if proc_name.starts_with("PID:") {
                format!("[{}]", &proc_name[4..])
            } else {
                proc_name.clone()
            };
            let proc_color = if proc_name.starts_with("PID:") || proc_name.starts_with('[') {
                Color::Rgb(90, 100, 125)
            } else {
                Color::Rgb(130, 200, 140)
            };

            // ── Remote Host (the star column) ──
            let (remote_display, remote_color) = match (&conn.dns_hostname, conn.remote_addr) {
                (Some(dns), _) if dns != "localhost" => {
                    (format!("\u{2192} {}", dns), Color::Rgb(100, 220, 255))
                }
                (Some(_), Some(ip)) if ip.is_loopback() => {
                    ("\u{2192} localhost".to_string(), Color::Rgb(75, 85, 108))
                }
                (None, Some(ip)) if ip.is_unspecified() => {
                    ("*".to_string(), Color::Rgb(55, 65, 85))
                }
                (None, Some(ip)) => {
                    (format!("\u{2192} {}", ip), Color::Rgb(155, 170, 195))
                }
                _ => ("*".to_string(), Color::Rgb(55, 65, 85)),
            };
            let remote_bold = conn.dns_hostname.is_some()
                && conn.dns_hostname.as_deref() != Some("localhost");

            // ── Service (port + label + protocol) ──
            let port = conn.remote_port.unwrap_or(conn.local_port);
            let proto = conn.proto.label();
            let service_str = if let Some(svc) = port_service_name(port) {
                format!("{}/{}", svc, proto)
            } else {
                format!("{}/{}", port, proto)
            };
            let service_color = match port_service_name(port) {
                Some("HTTPS") => Color::Rgb(80, 200, 120),
                Some("HTTP") => Color::Rgb(220, 180, 60),
                Some("DNS") => Color::Rgb(100, 180, 255),
                Some("SSH") => Color::Rgb(180, 130, 255),
                Some("RDP") => Color::Rgb(255, 150, 100),
                _ => Color::Rgb(180, 170, 130),
            };

            // ── State ──
            let state_str = conn
                .state
                .as_ref()
                .map(|s| s.label().to_string())
                .unwrap_or_else(|| "-".to_string());
            let state_color = conn
                .state
                .as_ref()
                .map(|s| s.color())
                .unwrap_or(Color::Rgb(80, 100, 140));

            // ── Local port ──
            let local_str = conn.local_port.to_string();

            // Row dimming for passive states
            let dim = matches!(
                conn.state.as_ref(),
                Some(TcpState::Listen)
                    | Some(TcpState::Closed)
                    | Some(TcpState::TimeWait)
                    | Some(TcpState::DeleteTcb)
            );
            let row_bg = if dim {
                Color::Rgb(8, 10, 18)
            } else {
                Color::Rgb(12, 16, 28)
            };

            Row::new(vec![
                Cell::from(Span::styled(proc_display, Style::default().fg(proc_color))),
                Cell::from(Span::styled(
                    remote_display,
                    Style::default().fg(remote_color).add_modifier(
                        if remote_bold && !dim {
                            Modifier::BOLD
                        } else {
                            Modifier::empty()
                        },
                    ),
                )),
                Cell::from(Span::styled(
                    service_str,
                    Style::default().fg(if dim {
                        Color::Rgb(70, 80, 100)
                    } else {
                        service_color
                    }),
                )),
                Cell::from(Span::styled(
                    state_str,
                    Style::default()
                        .fg(state_color)
                        .add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    local_str,
                    Style::default().fg(Color::Rgb(75, 85, 108)),
                )),
            ])
            .style(Style::default().bg(row_bg))
        })
        .collect();

    // ── Title bar with tabs ──
    let filter_info = if app.filter_text.is_empty() {
        String::new()
    } else {
        format!(" [filter: {}]", app.filter_text)
    };
    let localhost_info = if app.hide_localhost_conn {
        " \u{1F310} WAN"
    } else {
        " \u{1F517} ALL"
    };

    let mut title_spans = tab_title_spans(&app.bottom_tab);
    title_spans.push(Span::styled(
        format!("  {} connections ", total),
        Style::default().fg(Color::Rgb(100, 120, 150)),
    ));
    title_spans.push(Span::styled(
        localhost_info.to_string(),
        Style::default().fg(Color::Rgb(80, 160, 200)),
    ));
    if !filter_info.is_empty() {
        title_spans.push(Span::styled(
            filter_info,
            Style::default().fg(Color::Yellow),
        ));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(18),  // Process
            Constraint::Min(28),     // Remote Host (widest — the star)
            Constraint::Length(14),  // Service
            Constraint::Length(14),  // State
            Constraint::Length(7),   // Local port
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(Line::from(title_spans))
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
        let mut sb_state =
            ScrollbarState::new(total.saturating_sub(visible_height)).position(scroll);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(Color::Rgb(40, 70, 120))),
            sb_area,
            &mut sb_state,
        );
    }
}

// ─── Tab header spans ────────────────────────────────────────────────────────

/// Generate tab header spans with active highlighting.
pub fn tab_title_spans(active: &BottomTab) -> Vec<Span<'static>> {
    let traffic_style = if *active == BottomTab::Traffic {
        Style::default()
            .fg(Color::Rgb(80, 190, 255))
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default().fg(Color::Rgb(65, 80, 110))
    };
    let conn_style = if *active == BottomTab::Connections {
        Style::default()
            .fg(Color::Rgb(80, 190, 255))
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::default().fg(Color::Rgb(65, 80, 110))
    };

    vec![
        Span::styled(" [1] Traffic ", traffic_style),
        Span::styled(" [2] Connections ", conn_style),
    ]
}
