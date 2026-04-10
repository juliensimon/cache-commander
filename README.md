# ccmd — Cache Commander

[![CI](https://github.com/juliensimon/cache-commander/actions/workflows/ci.yml/badge.svg)](https://github.com/juliensimon/cache-commander/actions/workflows/ci.yml)
[![Release](https://github.com/juliensimon/cache-commander/actions/workflows/release.yml/badge.svg)](https://github.com/juliensimon/cache-commander/releases)
[![GitHub release](https://img.shields.io/github/v/release/juliensimon/cache-commander)](https://github.com/juliensimon/cache-commander/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org)
[![macOS](https://img.shields.io/badge/macOS-x86__64%20%7C%20ARM-black?logo=apple)](https://github.com/juliensimon/cache-commander/releases)
[![Linux](https://img.shields.io/badge/Linux-x86__64%20%7C%20ARM-black?logo=linux&logoColor=white)](https://github.com/juliensimon/cache-commander/releases)
[![crates.io](https://img.shields.io/crates/v/ccmd)](https://crates.io/crates/ccmd)
[![Homebrew](https://img.shields.io/badge/Homebrew-tap-brown?logo=homebrew)](https://github.com/juliensimon/homebrew-tap)

A terminal UI (TUI) for exploring, auditing, and cleaning developer cache directories on macOS and Linux. Scan cached packages for known CVEs, find outdated dependencies, and reclaim disk space — all from one tool.

Developer machines accumulate tens of gigabytes of invisible cache data — ML models, package archives, build artifacts, downloaded bottles. `ccmd` makes it all visible, scannable for vulnerabilities, and safely deletable.

![Cache Commander screenshot](screenshot.png)

## Why

- **ML models** (HuggingFace, PyTorch, Whisper) — tens of GB you forgot about
- **Package caches** (pip, uv, npm, Yarn, pnpm, Bun, Cargo, Homebrew) — old versions with known CVEs
- **npm supply chain risk** — transitive deps with install scripts hiding in npx cache
- **Build artifacts** (pre-commit hooks, Prisma engines) — stale and re-downloadable

`ccmd` gives you a single view across all of them with security scanning built in.

## Install

### Homebrew (macOS and Linux, includes MCP)

```bash
brew tap juliensimon/tap
brew install ccmd
```

### From crates.io

```bash
cargo install ccmd                  # TUI only
cargo install ccmd --features mcp   # TUI + MCP server for AI integration
```

### With cargo-binstall (prebuilt, includes MCP)

```bash
cargo binstall ccmd
```

### From source

```bash
git clone https://github.com/juliensimon/cache-commander
cd cache-commander
cargo build --release
./target/release/ccmd
```

### Prebuilt binaries (includes MCP)

Download from [GitHub Releases](https://github.com/juliensimon/cache-commander/releases) — available for macOS (x86_64, Apple Silicon) and Linux (x86_64, aarch64).

## Quick Start

```bash
ccmd                            # browse all default cache locations
ccmd --vulncheck                # scan for CVEs on startup
ccmd --versioncheck             # check for outdated packages on startup
ccmd --root ~/.cache/huggingface  # scan a specific directory
```

## Features

### Browse and Understand

- **Two-pane TUI** — navigable tree on the left, details on the right
- **15 cache providers** — semantic names instead of hash directories
- **Safety levels** — green (safe to delete), yellow (may cause rebuilds), red (contains state)
- **Sort** by size, name, or last modified
- **Search** with `/` — case-insensitive filter across the tree

### Security Scanning

- **Vulnerability scanning** — queries [OSV.dev](https://osv.dev) for known CVEs in cached packages
- **Version checking** — compares cached versions against PyPI, crates.io, and npm registries
- **Fix versions** — shows which version resolves each CVE, with upgrade commands
- **npm supply chain** — scans transitive deps in npx cache, flags packages with install scripts
- **Filter by status** — dim non-vulnerable items to focus on what matters
- **Copy upgrade command** — press `c` to copy `pip install pkg>=version` to clipboard

### Clean Up

- **Mark and delete** — Space to mark, `d` to delete with confirmation
- **Bulk mark** — `m` marks all visible (non-dimmed) items after filtering
- **Workflow**: scan (`V`) → filter (`f`) → mark all (`m`) → delete (`d`)

## Platform Support

**macOS and Linux only.** Windows is not supported. Path detection, cache directory resolution, and provider logic all assume Unix-style paths.

## Supported Caches

| Provider | Location | Semantic names |
|----------|----------|----------------|
| HuggingFace | `~/.cache/huggingface` | Model/dataset names, revisions |
| pip | `~/.cache/pip` | Wheel packages |
| uv | `~/.cache/uv` | Package names via dist-info |
| npm | `~/.npm` | npx packages + transitive node_modules deps |
| Homebrew | `~/Library/Caches/Homebrew` | Bottles, casks |
| Cargo | `~/.cargo/registry` | Crate names and versions |
| pre-commit | `~/.cache/pre-commit` | Hook repo names |
| Whisper | `~/.cache/whisper` | Model names (Large v3, Tiny, etc.) |
| GitHub CLI | `~/.cache/gh` | Workflow run logs |
| PyTorch | `~/.cache/torch` | Model checkpoints |
| Chroma | `~/.cache/chroma` | Embedding models |
| Prisma | `~/.cache/prisma` | Engine versions |
| Yarn | `~/.yarn-cache`, `.yarn/cache` | Package names and versions |
| pnpm | `~/.pnpm-store` | Package names and versions |
| Bun | `~/.bun/install/cache` | Package names and versions |

## Key Bindings

### Navigation

| Key | Action |
|-----|--------|
| `↑`/`k` `↓`/`j` | Move up / down |
| `→`/`l` `←`/`h` | Expand / Collapse (or go to parent) |
| `Enter` | Toggle expand |
| `g` / `G` | Jump to top / bottom |
| `/` | Search — type to filter, Enter to keep, Esc to clear |

### Security

| Key | Action |
|-----|--------|
| `v` / `V` | Scan selected / all for CVEs |
| `o` / `O` | Check selected / all for outdated versions |
| `f` | Cycle status filter: none → vuln → outdated → both |
| `c` | Copy upgrade command to clipboard |

### Marking and Deleting

| Key | Action |
|-----|--------|
| `Space` | Mark / unmark item |
| `Shift+Space` | Unmark all |
| `m` | Mark all visible items (with confirmation) |
| `u` | Unmark all |
| `d` / `D` | Delete marked items |

### Other

| Key | Action |
|-----|--------|
| `s` | Cycle sort (size → name → modified) |
| `r` / `R` | Refresh selected / all |
| `?` | Help overlay |
| `q` / `Ctrl+C` | Quit |

## Configuration

Create `~/.config/ccmd/config.toml`:

```toml
roots = ["~/.cache", "~/Library/Caches", "~/.npm", "~/.cargo/registry"]
sort_by = "size"          # size | name | modified
sort_desc = true
confirm_delete = true

[vulncheck]
enabled = false           # set true to scan on startup

[versioncheck]
enabled = false           # set true to check on startup
```

CLI flags override config file values.

## How It Works

### Cache Detection

`ccmd` walks your cache directories and identifies providers by directory name and structure. Each provider has custom logic to decode semantic names — for example, HuggingFace stores models in directories like `models--meta-llama--Llama-3.1-8B`, which ccmd displays as `[model] meta-llama/Llama-3.1-8B`.

### Vulnerability Scanning

When you press `V` (or pass `--vulncheck`):

1. `ccmd` walks the cache tree to discover packages with identifiable name + version
2. Sends a batch query to the [OSV.dev API](https://osv.dev) (chunked to 100 packages per request)
3. For each vulnerability found, fetches the detailed advisory to extract fix versions
4. Filters out vulnerabilities already fixed by the installed version
5. Displays results in the detail panel with fix version, upgrade command, and advisory link

### npm Supply Chain Detection

The npx cache (`~/.npm/_npx/`) contains full `node_modules` trees. `ccmd` scans every transitive dependency for:

- **Known CVEs** via OSV.dev
- **Install scripts** (`preinstall`, `install`, `postinstall`) — the primary vector for supply chain attacks
- **Dependency depth** — whether a package is a direct dependency or deep transitive

### Filter and Clean Workflow

The intended workflow for cleaning vulnerable packages:

1. **Scan**: Press `V` to scan all packages for CVEs
2. **Filter**: Press `f` to show only vulnerable items (non-matching items are dimmed)
3. **Review**: Navigate to see fix versions and upgrade commands
4. **Mark**: Press `m` to mark all vulnerable items for deletion
5. **Delete**: Press `d` to delete — frees space and forces fresh downloads

## MCP Server (AI Integration)

`ccmd` includes an [MCP](https://modelcontextprotocol.io) server that lets AI assistants like Claude query and manage your caches conversationally. Build with the `mcp` feature and run `ccmd mcp` to start the stdio transport.

```bash
# Install with MCP support
cargo install ccmd --features mcp

# Or build from source
cargo build --release --features mcp
```

Configure in Claude Code:

```bash
claude mcp add ccmd -s user -- ccmd mcp
```

Then ask Claude things like:

> "list my caches"

```
┌──────────────────┬────────────┬───────┐
│     Provider     │    Size    │ Items │
├──────────────────┼────────────┼───────┤
│ HuggingFace Hub  │ 28.93 GiB  │ 447   │
│ ~/Library/Caches │ 11.18 GiB  │ 234   │
│ uv               │ 3.16 GiB   │ 149   │
│ Homebrew         │ 1.55 GiB   │ 170   │
│ Cargo            │ 719.77 MiB │ 614   │
│ ...              │            │       │
└──────────────────┴────────────┴───────┘
Total: ~53.6 GiB across 2,167 items
```

> "find the most vulnerable npm packages"

![Vulnerable npm packages](ccmd-mcp-vuln-npm.png)

> "find outdated packages in my cache"

![Outdated packages](ccmd-mcp-outdated-uv.png)

Available tools: `list_caches`, `get_summary`, `search_packages`, `get_package_details`, `scan_vulnerabilities`, `check_outdated`, `preview_delete`, `delete_packages`. See [docs/mcp.md](docs/mcp.md) for full details.

## Architecture

```
src/
├── main.rs              # CLI bootstrap, terminal setup, subcommand routing
├── config.rs            # TOML config + CLI flag merging
├── app.rs               # Event loop, key handling, rendering
├── tree/
│   ├── node.rs          # TreeNode, CacheKind enum
│   └── state.rs         # TreeState, FilterMode, visibility, marking
├── scanner/
│   ├── mod.rs           # Background scan orchestrator, package discovery
│   └── walker.rs        # Directory traversal, size calculation
├── providers/
│   ├── mod.rs           # Provider dispatch, safety levels, upgrade commands
│   ├── huggingface.rs   # HuggingFace Hub semantic decoding
│   ├── pip.rs, uv.rs    # Python package providers
│   ├── npm.rs           # npm + npx + node_modules scanning
│   ├── cargo.rs         # Rust crate provider
│   └── ...              # 10 more providers
├── security/
│   ├── mod.rs           # Scan orchestration, vulnerability filtering
│   ├── osv.rs           # OSV.dev API, version comparison, fix extraction
│   └── registry.rs      # PyPI, crates.io, npm registry lookups
├── mcp/                 # MCP server (optional, behind `mcp` feature flag)
│   ├── mod.rs           # ServerHandler, tool routing, cache scanning
│   ├── tools.rs         # Tool parameter and response types
│   └── safety.rs        # Delete safety enforcement
└── ui/
    ├── tree_panel.rs    # Left pane — tree with status icons
    ├── detail_panel.rs  # Right pane — metadata, vulns, guidance
    ├── dialogs.rs       # Delete confirmation, help overlay
    └── theme.rs         # Color and style constants
```

- **No async runtime for TUI** — pure `std::thread` + `mpsc::channel`
- **MCP server uses tokio** — optional feature flag, only compiled when needed
- **Flat arena tree** — avoids recursive structs and borrow checker issues
- **Background scanning** — UI stays responsive during API calls and directory walks

## Contributing

Contributions and feedback are welcome!

- **Bug reports & feature requests** — [open an issue](https://github.com/juliensimon/cache-commander/issues)
- **Pull requests** — fork the repo, create a branch, and submit a PR. Please run `cargo fmt` and `cargo clippy` before submitting.
- **New cache providers** — adding support for a new tool? See `src/providers/` for examples. Each provider is a single file with a detection function and a name decoder.
- **Questions & ideas** — feel free to start a [discussion](https://github.com/juliensimon/cache-commander/discussions) or reach out directly.

## Author

**Julien Simon** — [julien@julien.org](mailto:julien@julien.org) — [github.com/juliensimon](https://github.com/juliensimon)

## License

MIT — see [LICENSE](LICENSE) for details.
