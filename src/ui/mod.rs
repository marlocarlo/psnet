pub mod connections;
pub mod dashboard;
pub mod detail_popup;
pub mod packets;
pub mod packets_tab;
pub mod servers;
pub mod speed;
pub mod status;
pub mod title;
pub mod topology;
pub mod alerts;
pub mod devices;
pub mod firewall;
pub mod networks;
pub mod widgets;

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

use crate::app::App;
use crate::types::BottomTab;

/// Master draw function — lays out all panes.
pub fn draw(f: &mut Frame, app: &mut App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Title bar
            Constraint::Length(11), // Speed section
            Constraint::Length(1),  // Tab menu
            Constraint::Min(10),   // Bottom pane (tab content)
            Constraint::Length(7),  // Wire preview (packet sniffer)
            Constraint::Length(1),  // Status bar (key hints)
        ])
        .split(f.area());

    title::draw_title_bar(f, main_layout[0], app);
    speed::draw_speed_section(f, main_layout[1], app);
    status::draw_tab_menu(f, main_layout[2], app);

    match app.bottom_tab {
        BottomTab::Dashboard => dashboard::draw_dashboard(f, main_layout[3], app),
        BottomTab::Connections => connections::draw_connections(f, main_layout[3], app),
        BottomTab::Servers => servers::draw_servers(f, main_layout[3], app),
        BottomTab::Packets => packets_tab::draw_packets_tab(f, main_layout[3], app),
        BottomTab::Topology => topology::draw_topology(f, main_layout[3], app),
        BottomTab::Alerts => alerts::draw_alerts(f, main_layout[3], app),
        BottomTab::Firewall => firewall::draw_firewall(f, main_layout[3], app),
        BottomTab::Devices => devices::draw_devices(f, main_layout[3], app),
        BottomTab::Networks => networks::draw_networks(f, main_layout[3], app),
    }

    packets::draw_packet_preview(f, main_layout[4], &app.sniffer);
    status::draw_key_hints(f, main_layout[5], app);

    // Detail popup overlay — drawn last so it appears on top of everything
    detail_popup::draw_detail_popup(f, app);
}
