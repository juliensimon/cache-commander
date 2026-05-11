mod app;
mod config;
#[cfg(feature = "mcp")]
mod mcp;
mod providers;
mod scanner;
mod security;
mod tree;
mod ui;
mod updater;

use app::App;
use config::Config;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use std::io;
use std::panic;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (config, _cli) = Config::load();

    // Check for MCP subcommand
    #[cfg(feature = "mcp")]
    if let Some(config::Command::Mcp) = _cli.command {
        return crate::mcp::run(config);
    }

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

    // Scanner channels — shutdown flag coordinates graceful exit.
    let (result_tx, result_rx) = mpsc::channel();
    let shutdown = Arc::new(AtomicBool::new(false));
    let scan_tx = scanner::start(result_tx, Some(Arc::clone(&shutdown)));

    // Background update-check channel
    let update_rx = updater::start(&config);

    // App
    let mut app = App::new(config, result_rx, scan_tx, update_rx);
    app.init();

    // Main loop
    loop {
        terminal.draw(|f| app.draw(f))?;
        if app.handle_event() {
            break;
        }
    }

    // Cleanup — signal scanner shutdown, then tear down terminal.
    shutdown.store(true, Ordering::Relaxed);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    Ok(())
}
