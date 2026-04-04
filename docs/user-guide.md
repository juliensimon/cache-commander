# ccmd User Guide

## Getting Started

### Installation

#### Homebrew (macOS and Linux)

```bash
brew tap juliensimon/tap
brew install ccmd
```

#### From crates.io

```bash
cargo install ccmd
```

#### Prebuilt binaries

Download from [GitHub Releases](https://github.com/juliensimon/cache-commander/releases) for macOS (x86_64, Apple Silicon) and Linux (x86_64, aarch64). Extract and place `ccmd` in your `PATH`.

#### From source

```bash
git clone https://github.com/juliensimon/cache-commander
cd cache-commander
cargo build --release
./target/release/ccmd
```

### First Run

Launch `ccmd` with no arguments to scan your default cache locations:

```bash
ccmd
```

On macOS, this scans `~/.cache`, `~/Library/Caches`, `~/.npm`, and `~/.cargo/registry` (if they exist). On Linux, it scans `~/.cache`.

You'll see a two-pane interface: a navigable tree on the left and a detail panel on the right.

### Navigation Basics

Use arrow keys or vim keys to move around:

- **`j`/`k`** or **`↑`/`↓`** — move up and down
- **`l`** or **`→`** — expand a directory
- **`h`** or **`←`** — collapse, or jump to parent
- **`g`/`G`** — jump to top/bottom
- **`/`** — search (type to filter, Enter to keep filter, Esc to clear)

---

## Understanding the Display

### Tree View (Left Pane)

Each line shows:

```
▾ ⚠↓ huggingface    29.0 GiB
│  │  │              │
│  │  │              └─ size
│  │  └─ name (semantic when possible)
│  └─ status: ⚠ = vulnerable, ↓ = outdated
└─ ▾ expanded, ▸ collapsed
```

### Detail Panel (Right Pane)

When you select an item, the right panel shows:

- **Path** — full filesystem path
- **Size** — calculated recursively
- **Modified** — time since last change
- **Provider** — which cache system (pip, npm, Cargo, etc.)
- **Safety** — whether it's safe to delete
- **Vulnerabilities** — CVE IDs, severity scores, fix versions, upgrade commands
- **Version** — current vs latest, with upgrade command if outdated
- **Action** — contextual guidance on what to do

### Status Icons

| Icon | Meaning |
|------|---------|
| `⚠` | Has known vulnerabilities |
| `↓` | Has outdated packages |
| `⚠↓` | Both vulnerable and outdated |
| `●` | Marked for deletion |

### Safety Levels

| Icon | Level | Meaning |
|------|-------|---------|
| `●` | Safe | Pure cache — will be re-downloaded automatically |
| `◐` | Caution | Deleting may trigger rebuilds |
| `○` | Unsafe | Contains configuration or state |

---

## Security Scanning

### Scanning for Vulnerabilities

Press **`V`** to scan all cached packages against the [OSV.dev](https://osv.dev) vulnerability database. This finds known CVEs in your pip, uv, npm, and Cargo cached packages.

Press **`v`** (lowercase) to scan only the selected item and its children.

The scan:
1. Discovers packages with identifiable name + version across all caches
2. Queries OSV.dev in batches of 100
3. Fetches fix versions for each CVE found
4. Filters out CVEs already fixed by the installed version

Results appear as `⚠` icons in the tree and detailed CVE info in the right panel.

### Checking for Outdated Packages

Press **`O`** to check all packages against their registries (PyPI, crates.io, npm). Press **`o`** for just the selected item.

Outdated packages show `↓` in the tree and "Update available" in the detail panel.

### Auto-Scan on Startup

Add these to your config or command line:

```bash
ccmd --vulncheck              # scan for CVEs on startup
ccmd --versioncheck           # check versions on startup
ccmd --vulncheck --versioncheck  # both
```

Or in `~/.config/ccmd/config.toml`:

```toml
[vulncheck]
enabled = true

[versioncheck]
enabled = true
```

---

## Filtering by Status

After scanning, press **`f`** to cycle through status filters:

| Filter | What's visible | Dimmed |
|--------|----------------|--------|
| None | Everything | Nothing |
| `⚠ vuln` | Vulnerable items + their parents | Everything else |
| `↓ outdated` | Outdated items + their parents | Everything else |
| `⚠↓ both` | Vulnerable OR outdated | Everything else |

Dimmed items stay visible for context but are greyed out. Navigation (`j`/`k`) skips over them automatically.

The active filter is shown in the header bar: `filter: ⚠ vuln`.

### Combining Filters

The text filter (`/`) and status filter (`f`) work together:
- Text filter controls which items appear in the tree
- Status filter controls which visible items are dimmed

Example: press `/` and type `pip`, then press `f` to filter to vulnerable items — you'll see only vulnerable pip packages.

---

## npm Supply Chain Detection

`ccmd` scans the npx cache (`~/.npm/_npx/`) for supply chain risks in transitive dependencies.

For each npm package in `node_modules`, the detail panel shows:

- **Dep depth** — "direct" for top-level dependencies, "transitive (depth N)" for nested ones
- **⚠ Scripts** — warns about `preinstall`, `install`, or `postinstall` scripts (the primary vector for supply chain attacks)

Supply chain attacks typically target deep transitive dependencies that nobody audits. The combination of vulnerability scanning + install script detection + dependency depth gives you visibility into this risk.

---

## Deleting Cache Items

### Single Item

1. Navigate to the item
2. Press **`Space`** to mark it (shows `●`)
3. Press **`d`** to delete

### Multiple Items

1. Navigate and press **`Space`** on each item you want to delete
2. Press **`d`** to delete all marked items
3. Confirm in the dialog (press `y`)

### Bulk Delete After Filtering

The most powerful cleanup workflow:

1. Press **`V`** to scan for vulnerabilities
2. Press **`f`** to filter to vulnerable items only
3. Press **`m`** to mark all visible items (confirms count first)
4. Press **`d`** to delete all marked items
5. Confirm with **`y`**

This deletes only the vulnerable cached artifacts. Next time your package manager needs them, it will download the (hopefully patched) latest version.

### Safety

- Deletion is permanent — files are removed from disk
- The confirmation dialog shows item count, total space to be freed, and safety summary
- Pass `--no-confirm` to skip the dialog (use with caution)
- Press **`u`** to unmark all items if you change your mind

---

## Copying Upgrade Commands

When viewing a vulnerable or outdated package, press **`c`** to copy the upgrade command to your clipboard:

- pip/uv packages: `pip install requests>=2.32.0`
- npm packages: `npm install express@4.19.0`
- Cargo packages: `cargo update -p serde`

If clipboard access isn't available, the command is shown in the status bar.

---

## Configuration

### Config File

`~/.config/ccmd/config.toml`:

```toml
# Cache directories to scan
roots = ["~/.cache", "~/Library/Caches", "~/.npm", "~/.cargo/registry"]

# Sorting
sort_by = "size"          # size | name | modified
sort_desc = true          # largest first

# Safety
confirm_delete = true     # show confirmation dialog before deleting

# Auto-scan on startup
[vulncheck]
enabled = false

[versioncheck]
enabled = false
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--root PATH` | Scan a specific directory (can repeat) |
| `--sort FIELD` | Sort by `size`, `name`, or `modified` |
| `--no-confirm` | Skip delete confirmation |
| `--vulncheck` | Scan for CVEs on startup |
| `--versioncheck` | Check for outdated packages on startup |

CLI flags override config file values. If `--root` is specified, only those roots are scanned (not the defaults).

---

## Tips

### Reclaim Space Quickly

Sort by size (default) and expand the largest directories first. HuggingFace model caches are often the biggest targets — a single model can be 5-15 GB.

### Audit Before Deleting

Press `?` to see the help overlay. Select an item and check its safety level in the detail panel before deleting. Green (`●`) items are always safe — they'll be re-downloaded when needed.

### Regular Security Audits

Run `ccmd --vulncheck` periodically to check for new CVEs in your cached packages. Cached packages aren't actively used, but they can be pulled into new projects when your package manager serves them from cache instead of downloading fresh.

### Speed Up Scanning

The first vulnerability scan takes 10-30 seconds depending on how many packages you have and network latency to OSV.dev. Subsequent scans in the same session are faster because the tree is already built.
