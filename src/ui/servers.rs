//! Servers tab UI — Wappalyzer-inspired, category-grouped dashboard layout
//! showing all listening services on the PC with rich technology details.

use std::collections::HashMap;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState,
};
use ratatui::Frame;

use crate::app::App;
use crate::network::servers::types::{ListenProto, ListeningPort, ServerCategory};

// ─── Theme constants ─────────────────────────────────────────────────────────

const BG: Color = Color::Rgb(14, 18, 30);
const CARD_BG: Color = Color::Rgb(12, 16, 28);
const SEL_BG: Color = Color::Rgb(22, 38, 72);
const UNRESPONSIVE_BG: Color = Color::Rgb(8, 10, 18);
const HDR_FG: Color = Color::Rgb(160, 180, 220);
const BORDER: Color = Color::Rgb(40, 55, 80);
const DIM: Color = Color::Rgb(55, 65, 85);
const LABEL: Color = Color::Rgb(80, 95, 125);

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn cat_color(cat: &ServerCategory) -> Color {
    let (r, g, b) = cat.color();
    Color::Rgb(r, g, b)
}

fn port_color(port: u16) -> Color {
    if port <= 1023 {
        Color::Rgb(100, 220, 255)
    } else if port <= 9999 {
        Color::Rgb(80, 200, 120)
    } else {
        Color::Rgb(90, 100, 125)
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}\u{2026}", &s[..max.saturating_sub(1)])
    } else {
        s.to_string()
    }
}

fn category_priority(cat: &ServerCategory) -> u8 {
    match cat {
        ServerCategory::DevTool => 0,
        ServerCategory::AppRuntime | ServerCategory::WebServer | ServerCategory::WebFramework => 1,
        ServerCategory::Database => 2,
        ServerCategory::MessageBroker => 3,
        ServerCategory::Infrastructure => 4,
        ServerCategory::SystemService => 5,
        ServerCategory::Other => 9,
    }
}

// ─── Display row types ──────────────────────────────────────────────────────

/// Each server takes 2 visual lines; category headers take 1.
enum DisplayRow<'a> {
    CategoryHeader {
        category: ServerCategory,
        count: usize,
        collapsed: bool,
    },
    /// Line 1 of a server card: icon + name + version badge + port + proto + status
    ServerLine1 {
        server: &'a ListeningPort,
        server_index: usize,
        active_conns: usize,
    },
    /// Line 2 of a server card: description + process + extra info
    ServerLine2 {
        server: &'a ListeningPort,
        server_index: usize,
    },
}

impl<'a> DisplayRow<'a> {
    fn server_index(&self) -> Option<usize> {
        match self {
            Self::ServerLine1 { server_index, .. } | Self::ServerLine2 { server_index, .. } => {
                Some(*server_index)
            }
            Self::CategoryHeader { .. } => None,
        }
    }
}

// ─── Main draw function ──────────────────────────────────────────────────────

pub fn draw_servers(f: &mut Frame, area: Rect, app: &App) {
    let scanner = &app.servers_scanner;
    let all_servers = &scanner.servers;
    let filtered = scanner.filtered_servers();

    // ── Connection counts per local port (non-LISTEN) ──
    let conn_counts: HashMap<u16, usize> = {
        let mut map = HashMap::new();
        for conn in &app.connections {
            let is_listen = conn
                .state
                .as_ref()
                .map(|s| matches!(s, crate::types::TcpState::Listen))
                .unwrap_or(false);
            if !is_listen {
                *map.entry(conn.local_port).or_insert(0) += 1;
            }
        }
        map
    };

    // ── Stats ──
    let total = all_servers.len();
    let tcp_count = all_servers
        .iter()
        .filter(|s| matches!(s.proto, ListenProto::Tcp))
        .count();
    let udp_count = total - tcp_count;
    let responsive_count = all_servers.iter().filter(|s| s.is_responsive).count();

    // ── Group filtered servers by category ──
    let mut by_category: HashMap<ServerCategory, Vec<&ListeningPort>> = HashMap::new();
    for s in &filtered {
        by_category
            .entry(s.server_kind.category())
            .or_default()
            .push(s);
    }

    let mut categories: Vec<ServerCategory> = by_category.keys().cloned().collect();
    categories.sort_by_key(|c| category_priority(c));

    for servers in by_category.values_mut() {
        servers.sort_by_key(|s| s.port);
    }

    // ── Build flat display list (2 lines per server) ──
    let mut display_rows: Vec<DisplayRow> = Vec::new();
    let mut server_count: usize = 0;

    for cat in &categories {
        if let Some(servers) = by_category.get(cat) {
            let is_collapsed = scanner.collapsed_categories.contains(cat);
            display_rows.push(DisplayRow::CategoryHeader {
                category: cat.clone(),
                count: servers.len(),
                collapsed: is_collapsed,
            });
            if !is_collapsed {
                for s in servers {
                    let active = conn_counts.get(&s.port).copied().unwrap_or(0);
                    display_rows.push(DisplayRow::ServerLine1 {
                        server: s,
                        server_index: server_count,
                        active_conns: active,
                    });
                    display_rows.push(DisplayRow::ServerLine2 {
                        server: s,
                        server_index: server_count,
                    });
                    server_count += 1;
                }
            }
        }
    }

    let selected = if server_count > 0 {
        scanner.scroll_offset.min(server_count - 1)
    } else {
        0
    };

    // ── Layout: summary strip + main cards + detail bar ──
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Min(8),
            Constraint::Length(6),
        ])
        .split(area);

    // 1. Summary Dashboard
    draw_summary_strip(
        f,
        chunks[0],
        total,
        tcp_count,
        udp_count,
        responsive_count,
        scanner.is_scanning(),
        all_servers,
        &scanner.filter_text,
        server_count,
    );

    // 2. Category-Grouped Cards
    draw_category_cards(f, chunks[1], &display_rows, selected, server_count);

    // 3. Detail Bar
    draw_detail_bar(f, chunks[2], &filtered, selected, &conn_counts);
}

// ─── Summary Strip ───────────────────────────────────────────────────────────

fn draw_summary_strip(
    f: &mut Frame,
    area: Rect,
    total: usize,
    tcp_count: usize,
    udp_count: usize,
    responsive: usize,
    is_scanning: bool,
    all_servers: &[ListeningPort],
    filter_text: &str,
    filtered_count: usize,
) {
    let sep = || Span::styled("  \u{2502}  ", Style::default().fg(Color::Rgb(30, 42, 65)));

    // Line 1: Total + TCP/UDP + responsive + scan
    let mut l1 = vec![
        Span::styled(
            format!(" {} Listeners", total),
            Style::default()
                .fg(Color::Rgb(200, 220, 255))
                .add_modifier(Modifier::BOLD),
        ),
        sep(),
        Span::styled(
            format!("{} TCP", tcp_count),
            Style::default()
                .fg(Color::Rgb(100, 180, 255))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {} UDP", udp_count),
            Style::default()
                .fg(Color::Rgb(220, 180, 60))
                .add_modifier(Modifier::BOLD),
        ),
        sep(),
        Span::styled(
            format!("\u{25CF} {} Responsive", responsive),
            Style::default()
                .fg(Color::Rgb(80, 200, 120))
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if is_scanning {
        l1.push(sep());
        l1.push(Span::styled(
            "\u{25CC} Scanning\u{2026}",
            Style::default()
                .fg(Color::Rgb(220, 180, 60))
                .add_modifier(Modifier::BOLD),
        ));
    }

    // Line 2: Category badges with emoji icons and counts
    let mut cat_counts: HashMap<ServerCategory, usize> = HashMap::new();
    for s in all_servers {
        *cat_counts.entry(s.server_kind.category()).or_insert(0) += 1;
    }
    let mut cat_entries: Vec<_> = cat_counts.iter().collect();
    cat_entries.sort_by(|a, b| b.1.cmp(a.1));

    let mut l2: Vec<Span> = vec![Span::styled(" ", Style::default())];
    for (i, (cat, count)) in cat_entries.iter().enumerate() {
        if i > 0 {
            l2.push(Span::styled("  ", Style::default()));
        }
        let cc = cat_color(cat);
        l2.push(Span::styled(
            format!(" \u{25A0} {}({}) ", cat.label(), count),
            Style::default().fg(cc).add_modifier(Modifier::BOLD),
        ));
    }

    // Line 3: Top detected technologies with emoji icons
    let mut kind_counts: HashMap<(String, String), usize> = HashMap::new();
    for s in all_servers {
        let key = (s.display_icon().to_string(), s.display_name());
        *kind_counts.entry(key).or_insert(0) += 1;
    }
    let mut kind_entries: Vec<_> = kind_counts.iter().collect();
    kind_entries.sort_by(|a, b| b.1.cmp(a.1));

    let mut l3: Vec<Span> = vec![Span::styled(
        " Top: ",
        Style::default().fg(HDR_FG).add_modifier(Modifier::BOLD),
    )];
    for (i, ((icon, name), count)) in kind_entries.iter().take(8).enumerate() {
        if i > 0 {
            l3.push(Span::styled("  ", Style::default()));
        }
        l3.push(Span::styled(
            format!("{} {}\u{00D7}{}", icon, name, count),
            Style::default().fg(Color::Rgb(180, 195, 220)),
        ));
    }
    if kind_entries.is_empty() {
        l3.push(Span::styled(
            "No services detected yet",
            Style::default().fg(DIM),
        ));
    }

    // Line 4: Filter indicator
    let l4 = if !filter_text.is_empty() {
        Line::from(vec![
            Span::styled(
                " \u{1F50D} Filter: ",
                Style::default().fg(Color::Yellow),
            ),
            Span::styled(
                filter_text.to_string(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  ({} matches)", filtered_count),
                Style::default().fg(Color::Rgb(120, 140, 170)),
            ),
        ])
    } else {
        Line::from("")
    };

    let summary = Paragraph::new(vec![
        Line::from(l1),
        Line::from(l2),
        Line::from(l3),
        l4,
    ])
    .block(
        Block::default()
            .title(Span::styled(
                " \u{1F50C} Technology Profiler ",
                Style::default()
                    .fg(Color::Rgb(200, 220, 255))
                    .add_modifier(Modifier::BOLD),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER))
            .style(Style::default().bg(Color::Rgb(8, 12, 24))),
    );
    f.render_widget(summary, area);
}

// ─── Category-Grouped Cards ─────────────────────────────────────────────────

fn draw_category_cards(
    f: &mut Frame,
    area: Rect,
    display_rows: &[DisplayRow],
    selected: usize,
    _server_count: usize,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if display_rows.is_empty() {
        let msg = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  \u{1F50C} No listening services detected yet",
                Style::default()
                    .fg(Color::Rgb(100, 120, 160))
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(Span::styled(
                "  Services will appear as scanning completes. Press 's' to trigger a scan.",
                Style::default().fg(Color::Rgb(70, 85, 110)),
            )),
        ])
        .style(Style::default().bg(BG));
        f.render_widget(msg, inner);
        return;
    }

    let visible_height = inner.height as usize;

    // Find display index of the selected server's first line
    let selected_display_idx = display_rows
        .iter()
        .position(|r| {
            matches!(r, DisplayRow::ServerLine1 { server_index, .. } if *server_index == selected)
        })
        .unwrap_or(0);

    // Centered viewport
    let total_rows = display_rows.len();
    let viewport_start = if total_rows <= visible_height {
        0
    } else {
        let half = visible_height / 2;
        if selected_display_idx <= half {
            0
        } else if selected_display_idx >= total_rows.saturating_sub(half) {
            total_rows.saturating_sub(visible_height)
        } else {
            selected_display_idx.saturating_sub(half)
        }
    };

    let width = inner.width as usize;

    for (i, row) in display_rows
        .iter()
        .skip(viewport_start)
        .take(visible_height)
        .enumerate()
    {
        let row_area = Rect::new(inner.x, inner.y + i as u16, inner.width, 1);

        match row {
            DisplayRow::CategoryHeader { category, count, collapsed } => {
                render_category_header(f, row_area, category, *count, *collapsed, width);
            }
            DisplayRow::ServerLine1 {
                server,
                server_index,
                active_conns,
            } => {
                let is_sel = *server_index == selected;
                render_server_line1(f, row_area, server, is_sel, *active_conns);
            }
            DisplayRow::ServerLine2 {
                server,
                server_index,
            } => {
                let is_sel = *server_index == selected;
                render_server_line2(f, row_area, server, is_sel, width);
            }
        }
    }

    // Scrollbar
    if total_rows > visible_height {
        let sb_area = Rect {
            x: area.x + area.width - 1,
            y: inner.y,
            width: 1,
            height: inner.height,
        };
        let mut sb_state = ScrollbarState::new(total_rows.saturating_sub(visible_height))
            .position(viewport_start);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .style(Style::default().fg(Color::Rgb(40, 70, 120))),
            sb_area,
            &mut sb_state,
        );
    }
}

fn render_category_header(
    f: &mut Frame,
    area: Rect,
    category: &ServerCategory,
    count: usize,
    collapsed: bool,
    width: usize,
) {
    let cc = cat_color(category);
    let label = category.label().to_uppercase();
    let collapse_icon = if collapsed { "\u{25B6}" } else { "\u{25BC}" }; // ▶ / ▼
    let suffix = format!(" {} services ", count);
    let prefix = format!(" {} {} ", collapse_icon, label);
    let used = prefix.len() + suffix.len();
    let dash_count = if width > used { width - used } else { 0 };
    let dashes: String = "\u{2500}".repeat(dash_count);

    let line = Line::from(vec![
        Span::styled(
            prefix,
            Style::default().fg(cc).add_modifier(Modifier::BOLD),
        ),
        Span::styled(dashes, Style::default().fg(Color::Rgb(25, 35, 55))),
        Span::styled(suffix, Style::default().fg(cc)),
    ]);

    f.render_widget(
        Paragraph::new(line).style(Style::default().bg(Color::Rgb(10, 14, 25))),
        area,
    );
}

/// Line 1: emoji + technology name (bold, colored) + version badge + port:proto + status + conns
fn render_server_line1(
    f: &mut Frame,
    area: Rect,
    server: &ListeningPort,
    is_selected: bool,
    active_conns: usize,
) {
    let (kr, kg, kb) = server.server_kind.color();
    let kind_color = Color::Rgb(kr, kg, kb);

    let mut spans: Vec<Span> = Vec::new();

    // Selection indicator
    if is_selected {
        spans.push(Span::styled(
            " \u{25B8} ",
            Style::default()
                .fg(Color::Rgb(100, 200, 255))
                .add_modifier(Modifier::BOLD),
        ));
    } else {
        spans.push(Span::styled("   ", Style::default()));
    }

    // Emoji icon — uses display_icon() to show 📦 for identified programs instead of ❓
    spans.push(Span::styled(
        format!("{} ", server.display_icon()),
        Style::default().fg(kind_color),
    ));

    // Technology name (bold, colored by category) — uses runtime VersionInfo for Unknown
    let name = truncate(&server.display_name(), 22);
    spans.push(Span::styled(
        name,
        Style::default()
            .fg(kind_color)
            .add_modifier(Modifier::BOLD),
    ));

    // Version badge
    if let Some(ref ver) = server.version {
        spans.push(Span::styled(" ", Style::default()));
        spans.push(Span::styled(
            format!(" v{} ", truncate(ver, 12)),
            Style::default()
                .fg(Color::Rgb(220, 200, 100))
                .add_modifier(Modifier::BOLD),
        ));
    }

    // Spacer
    spans.push(Span::styled("  ", Style::default()));

    // Port:Proto badge
    let proto_label = match server.proto {
        ListenProto::Tcp => "TCP",
        ListenProto::Udp => "UDP",
    };
    spans.push(Span::styled(
        format!(":{}", server.port),
        Style::default()
            .fg(port_color(server.port))
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(
        format!("/{} ", proto_label),
        Style::default().fg(match server.proto {
            ListenProto::Tcp => Color::Rgb(80, 140, 220),
            ListenProto::Udp => Color::Rgb(180, 150, 50),
        }),
    ));

    // Status indicator
    if server.is_responsive {
        spans.push(Span::styled(
            " \u{25CF} UP ",
            Style::default()
                .fg(Color::Rgb(80, 200, 120))
                .add_modifier(Modifier::BOLD),
        ));
    } else {
        spans.push(Span::styled(
            " \u{25CB}    ",
            Style::default().fg(Color::Rgb(70, 80, 100)),
        ));
    }

    // TLS indicator
    if server.details.contains("TLS: yes") {
        spans.push(Span::styled(
            " \u{1F512} ",
            Style::default().fg(Color::Rgb(80, 200, 120)),
        ));
    }

    // Active connections
    if active_conns > 0 {
        let conns_color = if active_conns > 10 {
            Color::Rgb(255, 150, 100)
        } else {
            Color::Rgb(80, 200, 120)
        };
        spans.push(Span::styled(
            format!(" {}conn{}", active_conns, if active_conns == 1 { "" } else { "s" }),
            Style::default().fg(conns_color),
        ));
    }

    let row_bg = if is_selected {
        SEL_BG
    } else if !server.is_responsive {
        UNRESPONSIVE_BG
    } else {
        CARD_BG
    };

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(row_bg)),
        area,
    );
}

/// Line 2: description + process name + exe path / banner / title
fn render_server_line2(
    f: &mut Frame,
    area: Rect,
    server: &ListeningPort,
    is_selected: bool,
    width: usize,
) {
    let mut spans: Vec<Span> = Vec::new();

    // Indent to align under the technology name
    spans.push(Span::styled("     ", Style::default()));

    // Description — uses runtime VersionInfo for Unknown/Generic entries
    let desc = server.display_description();
    let desc_display = truncate(&desc, 42);
    spans.push(Span::styled(
        desc_display,
        Style::default().fg(Color::Rgb(100, 120, 155)),
    ));

    spans.push(Span::styled("  ", Style::default()));

    // Process name + PID
    spans.push(Span::styled(
        format!("{}", truncate(&server.process_name, 16)),
        Style::default().fg(Color::Rgb(110, 175, 120)),
    ));
    spans.push(Span::styled(
        format!("({})", server.pid),
        Style::default().fg(Color::Rgb(70, 85, 105)),
    ));

    // Remaining space: show the most useful extra info
    let remaining = width.saturating_sub(70); // approximate used chars
    if remaining > 5 {
        spans.push(Span::styled("  ", Style::default()));

        if let Some(ref title) = server.http_title {
            spans.push(Span::styled(
                format!("\u{201C}{}\u{201D}", truncate(title, remaining.min(30))),
                Style::default().fg(Color::Rgb(140, 160, 190)),
            ));
        } else if let Some(ref banner) = server.banner {
            let clean = banner.replace(['\r', '\n'], " ");
            spans.push(Span::styled(
                truncate(&clean, remaining.min(35)),
                Style::default().fg(Color::Rgb(120, 135, 160)),
            ));
        } else if !server.exe_path.is_empty() {
            spans.push(Span::styled(
                truncate(&server.exe_path, remaining.min(40)),
                Style::default().fg(Color::Rgb(70, 85, 110)),
            ));
        }
    }

    let row_bg = if is_selected {
        SEL_BG
    } else if !server.is_responsive {
        UNRESPONSIVE_BG
    } else {
        CARD_BG
    };

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(row_bg)),
        area,
    );
}

// ─── Detail Bar ──────────────────────────────────────────────────────────────

fn draw_detail_bar(
    f: &mut Frame,
    area: Rect,
    filtered: &[&ListeningPort],
    selected: usize,
    conn_counts: &HashMap<u16, usize>,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(Color::Rgb(8, 12, 24)));

    if filtered.is_empty() || selected >= filtered.len() {
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No server selected. Use \u{2191}\u{2193} to browse, Enter for full details.",
                Style::default().fg(DIM),
            )),
        ])
        .block(block);
        f.render_widget(empty, area);
        return;
    }

    let server = filtered[selected];
    let active = conn_counts.get(&server.port).copied().unwrap_or(0);
    let (kr, kg, kb) = server.server_kind.color();
    let kind_color = Color::Rgb(kr, kg, kb);
    let pipe = || Span::styled(" \u{2502} ", Style::default().fg(Color::Rgb(30, 42, 65)));

    // Line 1: Technology + Category + Port + Version + Status
    let ver = server.version.as_deref().unwrap_or("\u{2014}");
    let line1 = Line::from(vec![
        Span::styled(
            format!(" {} ", server.display_icon()),
            Style::default().fg(kind_color),
        ),
        Span::styled(
            server.display_name(),
            Style::default()
                .fg(kind_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {} ", server.server_kind.category().label()),
            Style::default().fg(cat_color(&server.server_kind.category())),
        ),
        pipe(),
        Span::styled(
            format!(":{}/{}", server.port, server.proto.label()),
            Style::default()
                .fg(port_color(server.port))
                .add_modifier(Modifier::BOLD),
        ),
        pipe(),
        Span::styled(
            format!("v{}", ver),
            Style::default().fg(Color::Rgb(200, 185, 90)),
        ),
        pipe(),
        Span::styled(
            if server.is_responsive {
                "\u{25CF} Responding"
            } else {
                "\u{25CB} Not responding"
            },
            Style::default().fg(if server.is_responsive {
                Color::Rgb(80, 200, 120)
            } else {
                Color::Rgb(90, 100, 125)
            }),
        ),
        pipe(),
        Span::styled(
            format!(
                "{} conn{}",
                active,
                if active == 1 { "" } else { "s" }
            ),
            Style::default().fg(if active > 0 {
                Color::Rgb(80, 200, 120)
            } else {
                LABEL
            }),
        ),
    ]);

    // Line 2: Process details
    let exe_display = if server.exe_path.is_empty() {
        "\u{2014}".to_string()
    } else {
        truncate(&server.exe_path, 60)
    };
    let line2 = Line::from(vec![
        Span::styled("  Process: ", Style::default().fg(LABEL)),
        Span::styled(
            server.process_name.clone(),
            Style::default().fg(Color::Rgb(110, 175, 120)),
        ),
        Span::styled(
            format!(" (PID {})", server.pid),
            Style::default().fg(Color::Rgb(80, 95, 120)),
        ),
        pipe(),
        Span::styled("Path: ", Style::default().fg(LABEL)),
        Span::styled(
            exe_display,
            Style::default().fg(Color::Rgb(120, 140, 170)),
        ),
    ]);

    // Line 3: Banner / Title / Bind / First seen / TLS
    let mut l3: Vec<Span> = vec![Span::styled("  ", Style::default())];
    if let Some(ref banner) = server.banner {
        let clean = banner.replace(['\r', '\n'], " ");
        l3.push(Span::styled("Banner: ", Style::default().fg(LABEL)));
        l3.push(Span::styled(
            truncate(&clean, 35),
            Style::default().fg(Color::Rgb(140, 155, 180)),
        ));
        l3.push(pipe());
    }
    if let Some(ref title) = server.http_title {
        l3.push(Span::styled("Title: ", Style::default().fg(LABEL)));
        l3.push(Span::styled(
            truncate(title, 25),
            Style::default().fg(Color::Rgb(140, 160, 190)),
        ));
        l3.push(pipe());
    }
    l3.push(Span::styled("Bind: ", Style::default().fg(LABEL)));
    l3.push(Span::styled(
        server.bind_addr.to_string(),
        Style::default().fg(Color::Rgb(120, 140, 170)),
    ));
    l3.push(pipe());
    l3.push(Span::styled("First: ", Style::default().fg(LABEL)));
    l3.push(Span::styled(
        server.first_seen.format("%H:%M:%S").to_string(),
        Style::default().fg(Color::Rgb(120, 140, 170)),
    ));
    let has_tls = server.details.contains("TLS: yes");
    if has_tls {
        l3.push(pipe());
        l3.push(Span::styled(
            "\u{1F512} TLS",
            Style::default()
                .fg(Color::Rgb(80, 200, 120))
                .add_modifier(Modifier::BOLD),
        ));
    }

    // Line 4: Detected technologies (Wappalyzer-style)
    let mut l4: Vec<Span> = Vec::new();
    if !server.detected_techs.is_empty() {
        l4.push(Span::styled("  Tech: ", Style::default().fg(LABEL)));
        for (i, tech) in server.detected_techs.iter().take(8).enumerate() {
            if i > 0 {
                l4.push(Span::styled(" \u{00B7} ", Style::default().fg(Color::Rgb(40, 50, 70))));
            }
            let display = if tech.version.is_empty() {
                tech.name.clone()
            } else {
                format!("{}/{}", tech.name, tech.version)
            };
            l4.push(Span::styled(
                display,
                Style::default().fg(Color::Rgb(180, 160, 240)),
            ));
            l4.push(Span::styled(
                format!(" [{}]", tech.category),
                Style::default().fg(Color::Rgb(80, 90, 110)),
            ));
        }
        if server.detected_techs.len() > 8 {
            l4.push(Span::styled(
                format!(" +{} more", server.detected_techs.len() - 8),
                Style::default().fg(DIM),
            ));
        }
    }

    let mut lines = vec![line1, line2, Line::from(l3)];
    if !l4.is_empty() {
        lines.push(Line::from(l4));
    }

    let detail = Paragraph::new(lines).block(block);
    f.render_widget(detail, area);
}
