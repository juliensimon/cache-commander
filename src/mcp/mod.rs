pub mod tools;

use crate::config::Config;

pub fn run(_config: Config) -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("MCP server not yet implemented");
    Ok(())
}
