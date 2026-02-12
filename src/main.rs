mod app;
mod network;
mod types;
mod ui;
mod utils;

use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyEventKind, KeyCode, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use crossterm::ExecutableCommand;
use ratatui::Terminal;

use app::App;

fn main() -> io::Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    // Init
    let mut networks = sysinfo::Networks::new_with_refreshed_list();
    let mut app = App::new(&networks);

    let tick_rate = Duration::from_millis(1000);
    let mut last_tick = Instant::now();

    // Initial data
    app.update(&mut networks);

    // Event loop
    loop {
        terminal.draw(|f| ui::draw(f, &app))?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::ZERO);

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    // Ctrl+C quits
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && (key.code == KeyCode::Char('c') || key.code == KeyCode::Char('C'))
                    {
                        break;
                    }
                    if app.handle_key(key.code) {
                        break;
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.update(&mut networks);
            last_tick = Instant::now();
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
