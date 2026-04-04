mod app;
mod config;
mod providers;
mod scanner;
mod security;
mod tree;
mod ui;

use app::App;
use config::Config;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::io;
use std::panic;
use std::sync::mpsc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::load();

    // Set up panic hook to restore terminal
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    // Terminal setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Scanner channels
    let (result_tx, result_rx) = mpsc::channel();
    let scan_tx = scanner::start(result_tx);

    // App
    let mut app = App::new(config, result_rx, scan_tx);
    app.init();

    // Main loop
    loop {
        terminal.draw(|f| app.draw(f))?;
        if app.handle_event() {
            break;
        }
    }

    // Cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    Ok(())
}
