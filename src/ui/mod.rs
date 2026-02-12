pub mod capture;
pub mod connections;
pub mod packets;
pub mod speed;
pub mod status;
pub mod title;

use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::Frame;

use crate::app::App;
use crate::types::BottomTab;

/// Master draw function — lays out all panes.
pub fn draw(f: &mut Frame, app: &App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Title bar
            Constraint::Length(11), // Speed section
            Constraint::Min(10),   // Bottom pane (tabs)
            Constraint::Length(7),  // Wire preview (packet sniffer)
            Constraint::Length(1), // Status bar
        ])
        .split(f.area());

    title::draw_title_bar(f, main_layout[0], app);
    speed::draw_speed_section(f, main_layout[1], app);

    match app.bottom_tab {
        BottomTab::Connections => connections::draw_connections(f, main_layout[2], app),
        BottomTab::Traffic => capture::draw_traffic(f, main_layout[2], app),
    }

    packets::draw_packet_preview(f, main_layout[3], &app.sniffer);
    status::draw_status_bar(f, main_layout[4], app);
}
