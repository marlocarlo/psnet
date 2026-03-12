//! Servers tab UI — clean card-based layout with category grouping.

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

// ─── Theme ──────────────────────────────────────────────────────────────────

const BG: Color = Color::Rgb(12, 15, 26);
const ROW_BG: Color = Color::Rgb(14, 18, 32);
const ROW_ALT_BG: Color = Color::Rgb(16, 20, 35);
const SEL_BG: Color = Color::Rgb(20, 36, 68);
const SEL_BORDER: Color = Color::Rgb(60, 120, 220);
const DIM_BG: Color = Color::Rgb(10, 12, 22);
const BORDER: Color = Color::Rgb(30, 42, 65);
const DIM: Color = Color::Rgb(50, 60, 80);
const LABEL: Color = Color::Rgb(70, 85, 110);
const TEXT: Color = Color::Rgb(150, 165, 195);
const BRIGHT: Color = Color::Rgb(200, 215, 240);
const GREEN: Color = Color::Rgb(70, 195, 110);
const YELLOW: Color = Color::Rgb(220, 185, 60);

// ─── Helpers ────────────────────────────────────────────────────────────────

fn cat_color(cat: &ServerCategory) -> Color {
    let (r, g, b) = cat.color();
    Color::Rgb(r, g, b)
}

fn port_color(port: u16) -> Color {
    if port <= 1023 {
        Color::Rgb(90, 180, 255)
    } else if port <= 9999 {
        Color::Rgb(70, 190, 110)
    } else {
        Color::Rgb(80, 95, 120)
    }
}

fn trunc(s: &str, max: usize) -> String {
    if s.len() > max && max > 1 {
        format!("{}\u{2026}", &s[..max.saturating_sub(1)])
    } else {
        s.to_string()
    }
}

fn cat_priority(cat: &ServerCategory) -> u8 {
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

// ─── Display row ────────────────────────────────────────────────────────────

enum Row<'a> {
    Header { cat: ServerCategory, count: usize, collapsed: bool },
    Entry  { server: &'a ListeningPort, idx: usize, conns: usize },
}

// ─── Main draw ──────────────────────────────────────────────────────────────

pub fn draw_servers(f: &mut Frame, area: Rect, app: &App) {
    let sc = &app.servers_scanner;
    let all = &sc.servers;
    let filtered = sc.filtered_servers();

    // Connection counts per port
    let conn_counts: HashMap<u16, usize> = {
        let mut m = HashMap::new();
        for c in &app.connections {
            let listen = c.state.as_ref().map(|s| matches!(s, crate::types::TcpState::Listen)).unwrap_or(false);
            if !listen { *m.entry(c.local_port).or_insert(0) += 1; }
        }
        m
    };

    // Group by category
    let mut by_cat: HashMap<ServerCategory, Vec<&ListeningPort>> = HashMap::new();
    for s in &filtered {
        by_cat.entry(s.server_kind.category()).or_default().push(s);
    }
    let mut cats: Vec<ServerCategory> = by_cat.keys().cloned().collect();
    cats.sort_by_key(|c| cat_priority(c));
    for v in by_cat.values_mut() { v.sort_by_key(|s| s.port); }

    // Build flat row list
    let mut rows: Vec<Row> = Vec::new();
    let mut entry_count: usize = 0;
    for cat in &cats {
        if let Some(servers) = by_cat.get(cat) {
            let collapsed = sc.collapsed_categories.contains(cat);
            rows.push(Row::Header { cat: cat.clone(), count: servers.len(), collapsed });
            if !collapsed {
                for s in servers {
                    let conns = conn_counts.get(&s.port).copied().unwrap_or(0);
                    rows.push(Row::Entry { server: s, idx: entry_count, conns });
                    entry_count += 1;
                }
            }
        }
    }

    let selected = if entry_count > 0 { sc.scroll_offset.min(entry_count - 1) } else { 0 };

    // Stats
    let tcp = all.iter().filter(|s| matches!(s.proto, ListenProto::Tcp)).count();
    let udp = all.len() - tcp;
    let up = all.iter().filter(|s| s.is_responsive).count();

    // Layout: header(2) + list(fill) + detail(5)
    let has_filter = !sc.filter_text.is_empty();
    let header_h = if has_filter { 3 } else { 2 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header_h),
            Constraint::Min(6),
            Constraint::Length(5),
        ])
        .split(area);

    draw_header(f, chunks[0], all.len(), tcp, udp, up, sc.is_scanning(), &sc.filter_text, entry_count);
    draw_list(f, chunks[1], &rows, selected);
    draw_detail(f, chunks[2], &filtered, selected, &conn_counts);
}

// ─── Compact header ─────────────────────────────────────────────────────────

fn draw_header(
    f: &mut Frame, area: Rect,
    total: usize, tcp: usize, udp: usize, up: usize,
    scanning: bool, filter: &str, filtered: usize,
) {
    let sep = Span::styled(" \u{2502} ", Style::default().fg(Color::Rgb(25, 35, 55)));

    let mut l1 = vec![
        Span::styled(format!(" \u{25C8} {} ", total), Style::default().fg(BRIGHT).add_modifier(Modifier::BOLD)),
        Span::styled("TCP ", Style::default().fg(Color::Rgb(80, 150, 240))),
        Span::styled(format!("{}", tcp), Style::default().fg(BRIGHT)),
        Span::styled("  UDP ", Style::default().fg(YELLOW)),
        Span::styled(format!("{}", udp), Style::default().fg(BRIGHT)),
        sep.clone(),
        Span::styled("\u{25CF} ", Style::default().fg(GREEN)),
        Span::styled(format!("{} up", up), Style::default().fg(TEXT)),
    ];
    if scanning {
        l1.push(sep.clone());
        l1.push(Span::styled("\u{25CC} scanning", Style::default().fg(YELLOW)));
    }

    let mut lines = vec![Line::from(l1)];

    if !filter.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(" \u{25B7} ", Style::default().fg(YELLOW)),
            Span::styled(filter.to_string(), Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled(format!("  {} match{}", filtered, if filtered == 1 { "" } else { "es" }), Style::default().fg(DIM)),
        ]));
    }

    let block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

// ─── Server list ────────────────────────────────────────────────────────────

fn draw_list(f: &mut Frame, area: Rect, rows: &[Row], selected: usize) {
    let block = Block::default()
        .borders(Borders::NONE)
        .style(Style::default().bg(BG));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if rows.is_empty() {
        let msg = Paragraph::new(Line::from(Span::styled(
            "  No services detected. Press 's' to scan.",
            Style::default().fg(DIM),
        ))).style(Style::default().bg(BG));
        f.render_widget(msg, inner);
        return;
    }

    let h = inner.height as usize;
    let w = inner.width as usize;

    // Find selected entry's display position
    let sel_pos = rows.iter().position(|r| matches!(r, Row::Entry { idx, .. } if *idx == selected)).unwrap_or(0);

    // Viewport centering
    let total = rows.len();
    let start = if total <= h { 0 }
    else {
        let half = h / 2;
        if sel_pos <= half { 0 }
        else if sel_pos >= total.saturating_sub(half) { total.saturating_sub(h) }
        else { sel_pos.saturating_sub(half) }
    };

    for (i, row) in rows.iter().skip(start).take(h).enumerate() {
        let y = inner.y + i as u16;
        let row_area = Rect::new(inner.x, y, inner.width, 1);

        match row {
            Row::Header { cat, count, collapsed } => {
                render_cat_header(f, row_area, cat, *count, *collapsed, w);
            }
            Row::Entry { server, idx, conns } => {
                render_entry(f, row_area, server, *idx == selected, *conns, w, *idx);
            }
        }
    }

    // Scrollbar
    if total > h {
        let sb_area = Rect { x: area.x + area.width - 1, y: inner.y, width: 1, height: inner.height };
        let mut state = ScrollbarState::new(total.saturating_sub(h)).position(start);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight).style(Style::default().fg(Color::Rgb(30, 50, 90))),
            sb_area, &mut state,
        );
    }
}

fn render_cat_header(f: &mut Frame, area: Rect, cat: &ServerCategory, count: usize, collapsed: bool, w: usize) {
    let cc = cat_color(cat);
    let icon = if collapsed { "\u{25B8}" } else { "\u{25BE}" };
    let label = cat.label().to_uppercase();
    let prefix = format!("  {} {} ", icon, label);
    let suffix = format!(" {} ", count);
    let fill_len = w.saturating_sub(prefix.len() + suffix.len());
    let fill: String = "\u{2508}".repeat(fill_len);

    let line = Line::from(vec![
        Span::styled(prefix, Style::default().fg(cc).add_modifier(Modifier::BOLD)),
        Span::styled(fill, Style::default().fg(Color::Rgb(20, 28, 45))),
        Span::styled(suffix, Style::default().fg(cc)),
    ]);
    f.render_widget(
        Paragraph::new(line).style(Style::default().bg(Color::Rgb(10, 13, 24))),
        area,
    );
}

fn render_entry(f: &mut Frame, area: Rect, s: &ListeningPort, sel: bool, conns: usize, w: usize, idx: usize) {
    let (kr, kg, kb) = s.server_kind.color();
    let kc = Color::Rgb(kr, kg, kb);

    let mut spans: Vec<Span> = Vec::new();

    // Selection gutter
    if sel {
        spans.push(Span::styled(" \u{25B8}", Style::default().fg(SEL_BORDER).add_modifier(Modifier::BOLD)));
    } else {
        spans.push(Span::styled("  ", Style::default()));
    }

    // Icon
    spans.push(Span::styled(format!(" {} ", s.display_icon()), Style::default().fg(kc)));

    // Name (bold) — max 20 chars
    let name_max = if w > 100 { 24 } else { 18 };
    spans.push(Span::styled(
        format!("{:<width$}", trunc(&s.display_name(), name_max), width = name_max),
        Style::default().fg(kc).add_modifier(Modifier::BOLD),
    ));

    // Port badge — right-aligned feel
    let proto_ch = match s.proto { ListenProto::Tcp => 't', ListenProto::Udp => 'u' };
    spans.push(Span::styled(
        format!(" :{:<5}/{} ", s.port, proto_ch),
        Style::default().fg(port_color(s.port)),
    ));

    // Status dot
    if s.is_responsive {
        spans.push(Span::styled("\u{25CF}", Style::default().fg(GREEN)));
    } else {
        spans.push(Span::styled("\u{25CB}", Style::default().fg(DIM)));
    }

    // TLS lock
    if s.details.contains("TLS: yes") {
        spans.push(Span::styled(" \u{1F512}", Style::default().fg(GREEN)));
    } else {
        spans.push(Span::styled("   ", Style::default()));
    }

    // Version (compact)
    if let Some(ref ver) = s.version {
        spans.push(Span::styled(
            format!(" v{}", trunc(ver, 8)),
            Style::default().fg(YELLOW),
        ));
    }

    // Active connections
    if conns > 0 {
        let cc = if conns > 10 { Color::Rgb(255, 140, 90) } else { GREEN };
        spans.push(Span::styled(format!(" \u{2022}{}", conns), Style::default().fg(cc)));
    }

    // Spacer + secondary info (process or description) — fill remaining width
    let used: usize = spans.iter().map(|sp| sp.content.len()).sum();
    let remaining = w.saturating_sub(used + 1);
    if remaining > 8 {
        spans.push(Span::styled("  ", Style::default()));
        // Show process name for known services, description for unknown
        let info = if !s.process_name.is_empty() && s.process_name != "System" {
            let stem = s.process_name.strip_suffix(".exe")
                .or_else(|| s.process_name.strip_suffix(".EXE"))
                .unwrap_or(&s.process_name);
            format!("{} ({})", stem, s.pid)
        } else {
            s.display_description()
        };
        spans.push(Span::styled(trunc(&info, remaining - 2), Style::default().fg(LABEL)));
    }

    let bg = if sel { SEL_BG }
    else if !s.is_responsive { DIM_BG }
    else if idx % 2 == 0 { ROW_BG }
    else { ROW_ALT_BG };

    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(bg)),
        area,
    );
}

// ─── Detail panel ───────────────────────────────────────────────────────────

fn draw_detail(
    f: &mut Frame, area: Rect,
    filtered: &[&ListeningPort], selected: usize,
    conn_counts: &HashMap<u16, usize>,
) {
    let block = Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG));

    if filtered.is_empty() || selected >= filtered.len() {
        let empty = Paragraph::new(Line::from(Span::styled(
            "  \u{2191}\u{2193} browse  Enter detail  o open  y copy  \u{2190} collapse  \u{2192} expand",
            Style::default().fg(DIM),
        ))).block(block);
        f.render_widget(empty, area);
        return;
    }

    let s = filtered[selected];
    let conns = conn_counts.get(&s.port).copied().unwrap_or(0);
    let (kr, kg, kb) = s.server_kind.color();
    let kc = Color::Rgb(kr, kg, kb);
    let pipe = || Span::styled(" \u{2502} ", Style::default().fg(Color::Rgb(25, 35, 55)));

    // Line 1: Identity
    let mut l1 = vec![
        Span::styled(format!(" {} ", s.display_icon()), Style::default().fg(kc)),
        Span::styled(s.display_name(), Style::default().fg(kc).add_modifier(Modifier::BOLD)),
        Span::styled(format!("  {}", s.server_kind.category().label()), Style::default().fg(cat_color(&s.server_kind.category()))),
        pipe(),
        Span::styled(format!(":{}/{}", s.port, s.proto.label()), Style::default().fg(port_color(s.port)).add_modifier(Modifier::BOLD)),
    ];
    if let Some(ref v) = s.version {
        l1.push(pipe());
        l1.push(Span::styled(format!("v{}", v), Style::default().fg(YELLOW)));
    }
    l1.push(pipe());
    l1.push(Span::styled(
        if s.is_responsive { "\u{25CF} up" } else { "\u{25CB} down" },
        Style::default().fg(if s.is_responsive { GREEN } else { DIM }),
    ));
    if conns > 0 {
        l1.push(pipe());
        l1.push(Span::styled(format!("{} conn", conns), Style::default().fg(TEXT)));
    }

    // Line 2: Process + path
    let exe = if s.exe_path.is_empty() { "\u{2014}".to_string() } else { trunc(&s.exe_path, 70) };
    let l2 = Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(&s.process_name, Style::default().fg(Color::Rgb(100, 170, 110))),
        Span::styled(format!(" ({})", s.pid), Style::default().fg(LABEL)),
        pipe(),
        Span::styled(exe, Style::default().fg(Color::Rgb(90, 105, 140))),
    ]);

    // Line 3: Detected techs or banner
    let mut l3_spans: Vec<Span> = vec![Span::styled("  ", Style::default())];
    if !s.detected_techs.is_empty() {
        for (i, t) in s.detected_techs.iter().take(6).enumerate() {
            if i > 0 { l3_spans.push(Span::styled("  ", Style::default())); }
            let label = if t.version.is_empty() { t.name.clone() } else { format!("{}/{}", t.name, t.version) };
            l3_spans.push(Span::styled(label, Style::default().fg(Color::Rgb(160, 145, 230))));
        }
        if s.detected_techs.len() > 6 {
            l3_spans.push(Span::styled(format!("  +{}", s.detected_techs.len() - 6), Style::default().fg(DIM)));
        }
    } else if let Some(ref title) = s.http_title {
        l3_spans.push(Span::styled(format!("\u{201C}{}\u{201D}", trunc(title, 50)), Style::default().fg(TEXT)));
    } else if let Some(ref banner) = s.banner {
        let clean = banner.replace(['\r', '\n'], " ");
        l3_spans.push(Span::styled(trunc(&clean, 60), Style::default().fg(LABEL)));
    } else {
        l3_spans.push(Span::styled(s.display_description(), Style::default().fg(LABEL)));
    }

    let detail = Paragraph::new(vec![Line::from(l1), l2, Line::from(l3_spans)])
        .block(block);
    f.render_widget(detail, area);
}
