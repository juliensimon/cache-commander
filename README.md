# ccmd — Cache Commander

A terminal UI for browsing and managing cache directories on macOS and Linux.

Developer machines accumulate tens of gigabytes of invisible cache data. `ccmd` makes it visible, understandable, and deletable.

```
  ╔═╗╔═╗╔╦╗╔╦╗
  ║  ║  ║║║ ║║  cache commander
  ╚═╝╚═╝╩ ╩═╩╝  49.5 GiB  │  4 roots  │  sort: size ↓  │  ? help
  ──────────────────────────────────────────────────────────────────
  ▾ ~/.cache       49.9 GB   │ huggingface
    ▾ huggingface  29.0 GB   │ ~/.cache/huggingface
      hub/         19.0 GB   │
        [model] meta-llama/… │ Size:     29.0 GB
        [model] openai/whi…  │ Provider: HuggingFace Hub
      xet/          9.3 GB   │
    ▸ pre-commit    5.0 GB   │ ● Safe to delete
    ▸ whisper       4.4 GB   │
  ▸ ~/Library      11.0 GB   │
  ──────────────────────────────────────────────────────────────────
  ↑↓ navigate  ←→ expand  d delete  s sort  r refresh  / search
```

## Features

- **Browse** cache directories in a navigable tree view
- **App-aware** — understands HuggingFace, pip, uv, npm, Homebrew, Cargo, pre-commit, Whisper, GitHub CLI, PyTorch, Chroma, and Prisma
- **Semantic names** — shows `[model] meta-llama/Llama-3.1-8B` instead of `models--meta-llama--Llama-3.1-8B`, decodes hashes across all providers
- **Safety indicators** — green/yellow/red safety levels for each cache entry
- **Sort** by size, name, or last modified
- **Filter** with `/` — case-insensitive search across the tree
- **Delete** individual items or bulk-select with confirmation dialog
- **Fast** — instant tree rendering with async background size computation
- **Configurable** — TOML config file + CLI flags
- **Lightweight** — ~2 MB binary, no runtime dependencies

## Supported Caches

| Cache | Location | What it shows |
|-------|----------|---------------|
| HuggingFace | `~/.cache/huggingface` | Model/dataset names, revisions, blob file names |
| pip | `~/.cache/pip` | Wheel packages, HTTP cache |
| uv | `~/.cache/uv` | Package names via dist-info, build artifacts |
| npm | `~/.npm` | npx package names, content cache |
| Homebrew | `~/Library/Caches/Homebrew` | Downloaded bottles, casks, API cache |
| Cargo | `~/.cargo/registry` | Crate names and versions |
| pre-commit | `~/.cache/pre-commit` | Repo names via git remote |
| Whisper | `~/.cache/whisper` | Model names (Large v3, Tiny, etc.) |
| GitHub CLI | `~/.cache/gh` | Workflow run log IDs |
| PyTorch | `~/.cache/torch` | Model checkpoint names |
| Chroma | `~/.cache/chroma` | Embedding model names |
| Prisma | `~/.cache/prisma` | Engine versions, platforms |

## Install

```bash
cargo install --path .
```

Or build from source:

```bash
git clone https://github.com/YOUR_USERNAME/ccmd
cd ccmd
cargo build --release
./target/release/ccmd
```

## Usage

```bash
ccmd                          # scan default cache locations
ccmd --root ~/.cache          # scan a specific root
ccmd --sort name              # sort by name instead of size
ccmd --no-confirm             # skip delete confirmation
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

Create `~/.config/ccmd/config.toml`:

```toml
roots = ["~/.cache", "~/Library/Caches", "~/.npm", "~/.cargo/registry"]
sort_by = "size"
sort_desc = true
confirm_delete = true
```

CLI flags override config file settings.

## License

MIT
