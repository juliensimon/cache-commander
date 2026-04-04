# cache-explorer

A terminal UI for browsing and managing cache directories on macOS and Linux.

Developer machines accumulate tens of gigabytes of invisible cache data. `cache-explorer` makes it visible, understandable, and deletable.

```
┌──────────────────────────────────────────────────────────┐
│ cache-explorer            61.0 GB │ Sort: size ↓ │ ? help│
├────────────────────────────┬─────────────────────────────┤
│ ▾ ~/.cache       49.9 GB   │ huggingface                 │
│   ▾ huggingface  29.0 GB   │ ~/.cache/huggingface        │
│     hub/         19.0 GB   │                             │
│       meta-llama/Llama-3   │ Size:     29.0 GB           │
│       openai/whisper-large │ Modified: 2 hours ago       │
│     xet/          9.3 GB   │ Provider: HuggingFace Hub   │
│   ▸ pre-commit    5.0 GB   │                             │
│   ▸ whisper       4.4 GB   │ ● Safe to delete            │
│ ▸ ~/Library      11.0 GB   │                             │
├────────────────────────────┴─────────────────────────────┤
│ ↑↓ navigate  ←→ expand  d delete  s sort  r refresh     │
└──────────────────────────────────────────────────────────┘
```

## Features

- **Browse** cache directories in a navigable tree view
- **App-aware** — understands HuggingFace, pip, uv, npm, Homebrew, Cargo, pre-commit, and Whisper cache formats
- **Semantic names** — shows "meta-llama/Llama-3.1-8B" instead of `models--meta-llama--Llama-3.1-8B`
- **Safety indicators** — green/yellow/red safety levels for each cache entry
- **Sort** by size, name, or last modified
- **Delete** individual items or bulk-select with confirmation dialog
- **Fast** — parallel directory scanning with jwalk, lazy expansion
- **Configurable** — TOML config file + CLI flags
- **Lightweight** — ~2 MB binary, no runtime dependencies

## Supported Caches

| Cache | Location | What it shows |
|-------|----------|---------------|
| HuggingFace | `~/.cache/huggingface` | Model/dataset names, revisions, file counts |
| pip | `~/.cache/pip` | Wheel packages, HTTP cache |
| uv | `~/.cache/uv` | Package archives, built wheels, index cache |
| npm | `~/.npm` | Content cache, logs, npx cache |
| Homebrew | `~/Library/Caches/Homebrew` | Downloaded bottles, casks, API cache |
| Cargo | `~/.cargo/registry` | Crate names and versions |
| pre-commit | `~/.cache/pre-commit` | Hook repositories |
| Whisper | `~/.cache/whisper` | Model names and sizes |

## Install

```bash
cargo install --path .
```

Or build from source:

```bash
git clone https://github.com/YOUR_USERNAME/cache-explorer
cd cache-explorer
cargo build --release
./target/release/cache-explorer
```

## Usage

```bash
cache-explorer                          # scan default cache locations
cache-explorer --root ~/.cache          # scan a specific root
cache-explorer --sort name              # sort by name instead of size
cache-explorer --no-confirm             # skip delete confirmation
```

## Key Bindings

| Key | Action |
|-----|--------|
| `↑`/`k`, `↓`/`j` | Navigate |
| `→`/`l`, `←`/`h` | Expand / Collapse |
| `Enter` | Toggle expand |
| `g` / `G` | Jump to top / bottom |
| `Space` | Mark for bulk delete |
| `d` | Delete selected |
| `D` | Delete all marked |
| `s` | Cycle sort (size → name → modified) |
| `r` / `R` | Refresh selected / all |
| `/` | Search / filter |
| `?` | Help |
| `q` | Quit |

## Configuration

Create `~/.config/cache-explorer/config.toml`:

```toml
roots = ["~/.cache", "~/Library/Caches", "~/.npm", "~/.cargo/registry"]
sort_by = "size"
sort_desc = true
confirm_delete = true
```

CLI flags override config file settings.

## License

MIT
