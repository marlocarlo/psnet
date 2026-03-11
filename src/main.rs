mod app;
mod network;
mod types;
mod ui;
mod utils;

use std::io;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyEventKind, KeyCode, KeyModifiers, EnableMouseCapture, DisableMouseCapture, MouseEventKind, MouseButton};
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
    io::stdout().execute(EnableMouseCapture)?;
    let backend = ratatui::backend::CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    // Init
    let mut networks = sysinfo::Networks::new_with_refreshed_list();
    let mut app = App::new(&networks);

    let tick_rate = Duration::from_millis(1000);
    let fast_poll_interval = Duration::from_millis(200);
    let mut last_tick = Instant::now();

    // Initial data
    app.update(&mut networks);

    // Track active tab to detect switches — a tab change triggers a full clear so that
    // psmux's vt100 parser cursor state (accumulated from dashboard braille/block widgets)
    // is reset before the new tab is drawn.
    let mut last_tab = app.bottom_tab;

    // Event loop
    let mut needs_redraw = true;

    loop {
        if needs_redraw {
            if app.bottom_tab != last_tab {
                terminal.clear()?;
                last_tab = app.bottom_tab;
            }
            terminal.draw(|f| {
                app.last_frame_size = f.area();
                ui::draw(f, &app);
            })?;
            needs_redraw = false;
        }

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::ZERO)
            .min(fast_poll_interval); // Cap at 200ms for responsive streaming

        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
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
                        needs_redraw = true;
                    }
                }
                Event::Mouse(mouse) => {
                    // Skip mouse move events — they don't change state but
                    // would cause unnecessary redraws (making live data appear
                    // to scroll on mouse movement)
                    match mouse.kind {
                        MouseEventKind::Moved | MouseEventKind::Drag(_) => {}
                        _ => {
                            if app.handle_mouse(mouse.kind, mouse.column, mouse.row) {
                                break;
                            }
                            needs_redraw = true;
                        }
                    }
                }
                Event::Resize(_, _) => {
                    needs_redraw = true;
                }
                _ => {}
            }
        }

        // Fast poll: drain streaming scanner buffers every 200ms
        if app.fast_poll() {
            needs_redraw = true;
        }

        if last_tick.elapsed() >= tick_rate {
            app.update(&mut networks);
            last_tick = Instant::now();
            needs_redraw = true;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    io::stdout().execute(DisableMouseCapture)?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
