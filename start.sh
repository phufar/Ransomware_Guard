#!/usr/bin/env bash
set -euo pipefail

# ─── Color helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ─── Resolve project root (where this script lives) ─────────────────────────
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"
SESSION_NAME="ransomware-guard"

# ═══════════════════════════════════════════════════════════════════════════════
#  1. Check system-level dependencies
# ═══════════════════════════════════════════════════════════════════════════════
info "Checking system dependencies…"

MISSING=()
command -v python3 >/dev/null 2>&1 || MISSING+=("python3")
command -v node    >/dev/null 2>&1 || MISSING+=("node")
command -v npm     >/dev/null 2>&1 || MISSING+=("npm")
command -v tmux    >/dev/null 2>&1 || MISSING+=("tmux")

if [[ ${#MISSING[@]} -gt 0 ]]; then
    error "Missing required commands: ${MISSING[*]}"
    error "Please install them before running this script."
    exit 1
fi

ok "python3 $(python3 --version 2>&1 | awk '{print $2}')"
ok "node    $(node --version)"
ok "npm     $(npm --version)"
ok "tmux    $(tmux -V)"

# ═══════════════════════════════════════════════════════════════════════════════
#  2. Backend – Python virtual-env & pip dependencies
# ═══════════════════════════════════════════════════════════════════════════════
info "Setting up backend…"

if [[ ! -d "$BACKEND_DIR/.venv" ]]; then
    warn "Virtual environment not found – creating one…"
    python3 -m venv "$BACKEND_DIR/.venv"
    ok "Virtual environment created"
fi

# shellcheck disable=SC1091
source "$BACKEND_DIR/.venv/bin/activate"
ok "Virtual environment activated"

info "Installing / updating Python dependencies…"
pip install --quiet --upgrade pip
pip install --quiet -r "$BACKEND_DIR/requirements.txt"
ok "Python dependencies ready"
deactivate

# ═══════════════════════════════════════════════════════════════════════════════
#  3. Frontend – npm dependencies
# ═══════════════════════════════════════════════════════════════════════════════
info "Setting up frontend…"

if [[ ! -d "$FRONTEND_DIR/node_modules" ]]; then
    warn "node_modules not found – running npm install…"
    npm install --prefix "$FRONTEND_DIR"
    ok "npm packages installed"
else
    ok "node_modules already present"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  4. Kill existing session if running
# ═══════════════════════════════════════════════════════════════════════════════
if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
    warn "Session '$SESSION_NAME' already exists – killing it…"
    tmux kill-session -t "$SESSION_NAME"
fi

# ═══════════════════════════════════════════════════════════════════════════════
#  5. Launch tmux with 3-pane layout
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
info "Starting tmux session: $SESSION_NAME"

# Step 1: Create session with status pane (top-left = pane 0)
tmux new-session -d -s "$SESSION_NAME" -n "guard" "bash $PROJECT_DIR/.tmux_status.sh"

# Step 2: Split vertically → right pane for backend (pane 1 = full right)
tmux split-window -h -t "$SESSION_NAME:guard.0" -l 55% "bash $PROJECT_DIR/.tmux_backend.sh"

# Step 3: Split left pane horizontally → bottom-left for frontend (pane 2)
tmux split-window -v -t "$SESSION_NAME:guard.0" -l 65% "bash $PROJECT_DIR/.tmux_frontend.sh"

# Select the backend pane by default
tmux select-pane -t "$SESSION_NAME:guard.2"

# ── Style the tmux bar ──────────────────────────────────────────────────────
tmux set-option -t "$SESSION_NAME" status on
tmux set-option -t "$SESSION_NAME" status-style "bg=colour235,fg=colour136"
tmux set-option -t "$SESSION_NAME" status-left "#[fg=colour46,bold]  Ransomware Guard "
tmux set-option -t "$SESSION_NAME" status-right "#[fg=colour75]Backend :8000 | Frontend :5173 #[fg=colour240]| %H:%M "
tmux set-option -t "$SESSION_NAME" status-left-length 30
tmux set-option -t "$SESSION_NAME" status-right-length 50
tmux set-option -t "$SESSION_NAME" pane-border-style "fg=colour238"
tmux set-option -t "$SESSION_NAME" pane-active-border-style "fg=colour46"

# Attach to the session
tmux attach-session -t "$SESSION_NAME"
