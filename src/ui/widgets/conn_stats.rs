//! Connection Stats KPI widget — live TCP state distribution, TCP/UDP split, connection count.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::types::{ConnProto, TcpState};

/// Snapshot of connection statistics for rendering.
pub struct ConnStats {
    pub total: usize,
    pub established: usize,
    pub time_wait: usize,
    pub close_wait: usize,
    pub syn_sent: usize,
    pub listen: usize,
    pub other: usize,
    pub tcp_count: usize,
    pub udp_count: usize,
}

impl ConnStats {
    pub fn from_connections(connections: &[crate::types::Connection]) -> Self {
        let mut s = ConnStats {
            total: connections.len(),
            established: 0,
            time_wait: 0,
            close_wait: 0,
            syn_sent: 0,
            listen: 0,
            other: 0,
            tcp_count: 0,
            udp_count: 0,
        };
        for c in connections {
            match c.proto {
                ConnProto::Tcp => s.tcp_count += 1,
                ConnProto::Udp => s.udp_count += 1,
            }
            match c.state.as_ref() {
                Some(TcpState::Established) => s.established += 1,
                Some(TcpState::TimeWait) => s.time_wait += 1,
                Some(TcpState::CloseWait) => s.close_wait += 1,
                Some(TcpState::SynSent) | Some(TcpState::SynReceived) => s.syn_sent += 1,
                Some(TcpState::Listen) => s.listen += 1,
                _ => s.other += 1,
            }
        }
        s
    }
}

/// Draw a compact connection stats widget.
pub fn draw_conn_stats(f: &mut Frame, area: Rect, stats: &ConnStats, tick: u64) {
    let bg = Color::Rgb(8, 12, 24);

    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(
                " Connections ",
                Style::default()
                    .fg(Color::Rgb(80, 200, 255))
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{} ", stats.total),
                Style::default()
                    .fg(Color::Rgb(255, 255, 255))
                    .add_modifier(Modifier::BOLD),
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(30, 50, 85)))
        .style(Style::default().bg(bg));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 1 || inner.width < 10 {
        return;
    }

    let mut lines: Vec<Line<'static>> = Vec::new();

    // Row 1: TCP state mini-bars
    let max_state = stats.established.max(1);
    let bar_w = inner.width.saturating_sub(16) as usize;

    // ESTABLISHED bar
    let est_bar_len = ((stats.established as f64 / max_state as f64) * bar_w as f64).ceil() as usize;
    let pulse_char = if tick % 2 == 0 && stats.established > 0 { "●" } else { "○" };
    lines.push(Line::from(vec![
        Span::styled(
            format!(" {} ", pulse_char),
            Style::default().fg(Color::Rgb(80, 220, 120)),
        ),
        Span::styled("EST  ", Style::default().fg(Color::Rgb(70, 90, 110))),
        Span::styled(
            format!("{:>4} ", stats.established),
            Style::default()
                .fg(Color::Rgb(80, 220, 120))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "█".repeat(est_bar_len.min(bar_w)),
            Style::default().fg(Color::Rgb(40, 140, 70)),
        ),
    ]));

    // TIME_WAIT
    if stats.time_wait > 0 || inner.height > 3 {
        let tw_bar = ((stats.time_wait as f64 / max_state.max(1) as f64) * bar_w as f64).ceil() as usize;
        lines.push(Line::from(vec![
            Span::styled("   ", Style::default()),
            Span::styled("TW   ", Style::default().fg(Color::Rgb(70, 90, 110))),
            Span::styled(
                format!("{:>4} ", stats.time_wait),
                Style::default().fg(Color::Rgb(180, 100, 255)),
            ),
            Span::styled(
                "█".repeat(tw_bar.min(bar_w)),
                Style::default().fg(Color::Rgb(120, 60, 180)),
            ),
        ]));
    }

    // CLOSE_WAIT + SYN on same line if space is tight
    if stats.close_wait > 0 || stats.syn_sent > 0 || inner.height > 4 {
        lines.push(Line::from(vec![
            Span::styled("   ", Style::default()),
            Span::styled("CW   ", Style::default().fg(Color::Rgb(70, 90, 110))),
            Span::styled(
                format!("{:>4} ", stats.close_wait),
                Style::default().fg(Color::Rgb(255, 140, 80)),
            ),
            Span::styled("  SYN ", Style::default().fg(Color::Rgb(70, 90, 110))),
            Span::styled(
                format!("{}", stats.syn_sent),
                Style::default().fg(Color::Rgb(255, 220, 80)),
            ),
        ]));
    }

    // LISTEN
    if stats.listen > 0 || inner.height > 5 {
        lines.push(Line::from(vec![
            Span::styled("   ", Style::default()),
            Span::styled("LISN ", Style::default().fg(Color::Rgb(70, 90, 110))),
            Span::styled(
                format!("{:>4} ", stats.listen),
                Style::default().fg(Color::Rgb(80, 180, 255)),
            ),
            Span::styled("  OTH ", Style::default().fg(Color::Rgb(70, 90, 110))),
            Span::styled(
                format!("{}", stats.other),
                Style::default().fg(Color::Rgb(100, 110, 130)),
            ),
        ]));
    }

    // TCP/UDP split bar
    if inner.height as usize > lines.len() + 1 {
        lines.push(Line::from(""));
        let split_w = inner.width.saturating_sub(4) as usize;
        let tcp_w = if stats.total > 0 {
            ((stats.tcp_count as f64 / stats.total as f64) * split_w as f64).round() as usize
        } else {
            0
        };
        let udp_w = split_w.saturating_sub(tcp_w);
        lines.push(Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(
                format!("TCP:{}", stats.tcp_count),
                Style::default().fg(Color::Rgb(80, 160, 255)).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" ", Style::default()),
            Span::styled(
                "▓".repeat(tcp_w.min(split_w)),
                Style::default().fg(Color::Rgb(40, 100, 180)),
            ),
            Span::styled(
                "░".repeat(udp_w.min(split_w)),
                Style::default().fg(Color::Rgb(80, 50, 120)),
            ),
            Span::styled(" ", Style::default()),
            Span::styled(
                format!("UDP:{}", stats.udp_count),
                Style::default().fg(Color::Rgb(180, 100, 255)).add_modifier(Modifier::BOLD),
            ),
        ]));
    }

    let paragraph = Paragraph::new(lines).style(Style::default().bg(bg));
    f.render_widget(paragraph, inner);
}
