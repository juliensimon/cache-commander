#!/usr/bin/env bash
# Replayable TUI smoke test: drives the real ccmd binary in tmux against a
# fabricated cache fixture and asserts provider semantic names and metadata
# render correctly. Covers the v0.4.2 provider fixes:
#   - pip http-v2 (pip >= 23.3)
#   - uv versioned buckets via prefix matching (sdists-v9, simple-v24, ...)
#   - pnpm 11 SQLite index.db labeling
#   - Xcode 26 WorkspacePath in DerivedData Info.plist
#
# Usage: scripts/tui-smoke-test.sh
#   CCMD_BIN=path/to/ccmd to test a specific binary (default: target/release/ccmd,
#   built automatically if missing).
#
# Requires: tmux. Exits non-zero on the first failed assertion, printing the
# captured pane for diagnosis.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="${CCMD_BIN:-target/release/ccmd}"
if [ ! -x "$BIN" ]; then
    echo "building release binary..."
    cargo build --release --quiet
fi

command -v tmux >/dev/null || { echo "FAIL: tmux is required"; exit 1; }

SESSION="ccmd-smoke-$$"
FIXTURE="$(mktemp -d)"
PANE=""

cleanup() {
    tmux kill-session -t "$SESSION" 2>/dev/null || true
    rm -rf "$FIXTURE"
}
trap cleanup EXIT

# --- fixture -----------------------------------------------------------------
mkdir -p \
    "$FIXTURE/caches/pip/http-v2/aa" \
    "$FIXTURE/caches/pip/selfcheck" \
    "$FIXTURE/caches/pip/wheels/aa/bb" \
    "$FIXTURE/caches/uv/environments-v2" \
    "$FIXTURE/caches/uv/git-v0" \
    "$FIXTURE/caches/uv/sdists-v9" \
    "$FIXTURE/caches/uv/simple-v24" \
    "$FIXTURE/caches/uv/wheels-v6" \
    "$FIXTURE/.pnpm-store/v11/files/00" \
    "$FIXTURE/Xcode/DerivedData/MyApp-abc123def"

echo x > "$FIXTURE/caches/pip/http-v2/aa/body"
echo x > "$FIXTURE/caches/pip/wheels/aa/bb/requests-2.31.0-py3-none-any.whl"
echo x > "$FIXTURE/caches/uv/sdists-v9/blob"
echo x > "$FIXTURE/.pnpm-store/v11/index.db"
echo x > "$FIXTURE/.pnpm-store/v11/index.db-wal"
echo x > "$FIXTURE/.pnpm-store/v11/index.db-shm"

# Xcode 26 writes WorkspacePath (not the legacy WORKSPACE_PATH).
cat > "$FIXTURE/Xcode/DerivedData/MyApp-abc123def/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>WorkspacePath</key>
    <string>/Users/dev/MyApp/MyApp.xcworkspace</string>
</dict>
</plist>
PLIST

# --- helpers -----------------------------------------------------------------
keys() { # send each argument as a key, with a short settle delay
    for k in "$@"; do
        tmux send-keys -t "$SESSION" "$k"
        sleep 0.3
    done
}

snap() { PANE="$(tmux capture-pane -t "$SESSION" -p)"; }

selected() { # display name of the selected node = first detail-panel line
    # The detail panel is right of the '│' divider; skip everything up to and
    # including the status bar (which also contains '│' and says "sort:").
    snap
    awk -F'│' 'seen && $2 ~ /[^ ]/ { gsub(/^ +| +$/, "", $2); print $2; exit }
               /sort:/ { seen = 1 }' <<<"$PANE"
}

navigate_to() { # walk Down from the current row until the selected node matches
    local target="$2" mode="$1" i cur
    for i in $(seq 1 30); do
        cur="$(selected)"
        case "$mode" in
            exact)    [ "$cur" = "$target" ] && return 0 ;;
            contains) case "$cur" in *"$target"*) return 0 ;; esac ;;
        esac
        tmux send-keys -t "$SESSION" Down
        sleep 0.2
    done
    echo "FAIL: never reached node '$target' (last selected: '$(selected)')"
    snap; echo "$PANE"
    exit 1
}

PASS=0
assert_pane() { # assert_pane <description> <expected substring>
    # The tree populates from a background scanner thread, so poll rather
    # than assuming content is present right after a keystroke.
    for _ in $(seq 1 10); do
        snap
        if grep -qF "$2" <<<"$PANE"; then
            echo "PASS: $1"
            PASS=$((PASS + 1))
            return 0
        fi
        sleep 0.5
    done
    echo "FAIL: $1 — expected to find: $2"
    echo "----- captured pane -----"
    echo "$PANE"
    exit 1
}

# --- run ---------------------------------------------------------------------
# Roots keep CLI order; children sort by name DESCENDING under --sort name.
# Navigation below never assumes exact rows — it walks down to the node it
# wants — but section order must follow the on-screen order top to bottom.
tmux new-session -d -s "$SESSION" -x 200 -y 50 \
    "$BIN --no-update-check --sort name --root '$FIXTURE/caches' --root '$FIXTURE/.pnpm-store' --root '$FIXTURE/Xcode/DerivedData'"
sleep 3

assert_pane "app launched with 3 roots" "3 roots"

# Navigation never assumes row order (the sort is descending and children
# populate asynchronously): each step expands a node, waits for its children
# via assert_pane, then walks Down until the wanted node is selected.

# Root 1: caches. Children are pip and uv; visit uv first since name sort
# is descending (u > p).
keys l
assert_pane "caches root expanded" "pip"

navigate_to exact "uv"
keys l
assert_pane "uv environments bucket" "Cached Environments"
assert_pane "uv git bucket" "Git Repositories"
assert_pane "uv sdists-v9 via prefix" "Source Distributions"
assert_pane "uv simple-v24 via prefix" "Package Index Cache"
assert_pane "uv wheels bucket" "Built Wheels"

navigate_to exact "Source Distributions"
assert_pane "uv sdists metadata" "Source distribution cache"

# pip children in descending name order: wheels, selfcheck, http-v2 — visit
# in that order since navigate_to only walks down.
navigate_to exact "pip"
keys l
assert_pane "pip http-v2 name preserved" "http-v2"

# Deep-dive one wheel: wheels/aa/bb/requests-...whl
navigate_to exact "wheels"
keys l
assert_pane "wheels expanded" "aa"
navigate_to exact "aa"
keys l
assert_pane "wheels/aa expanded" "bb"
navigate_to exact "bb"
keys l
assert_pane "pip wheel parsed" "requests 2.31.0"

navigate_to exact "http-v2"
assert_pane "pip http-v2 metadata" "HTTP response cache"

# Root 2: .pnpm-store -> v11 -> index.db (+ WAL/SHM sidecars)
navigate_to contains ".pnpm-store"
keys l
assert_pane "pnpm store v11" "Store v11"
navigate_to exact "Store v11"
keys l
assert_pane "pnpm sqlite index labeled" "Package Index (SQLite)"

# Root 3: DerivedData (Xcode 26 WorkspacePath key)
navigate_to contains "DerivedData"
keys l
assert_pane "xcode WorkspacePath resolved" "MyApp.xcworkspace (at /Users/dev/MyApp/MyApp.xcworkspace)"

keys q
echo "OK: $PASS assertions passed"
