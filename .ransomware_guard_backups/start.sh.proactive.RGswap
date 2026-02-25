#!/usr/bin/env bash
set -euo pipefail

# ─── Color helpers ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

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
#  5. Launch tmux with split panes
# ═══════════════════════════════════════════════════════════════════════════════
echo ""
info "Starting tmux session: $SESSION_NAME"

# Backend command
BACKEND_CMD="source '$BACKEND_DIR/.venv/bin/activate' && \
echo -e '${GREEN}═══════════════════════════════════════${NC}' && \
echo -e '${GREEN}  🛡️  BACKEND  (uvicorn :8000)${NC}' && \
echo -e '${GREEN}═══════════════════════════════════════${NC}' && \
echo '' && \
sudo '$BACKEND_DIR/.venv/bin/python' -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload \
    --app-dir '$BACKEND_DIR'"

# Frontend command
FRONTEND_CMD="echo -e '${GREEN}═══════════════════════════════════════${NC}' && \
echo -e '${GREEN}  🖥️  FRONTEND (vite :5173)${NC}' && \
echo -e '${GREEN}═══════════════════════════════════════${NC}' && \
echo '' && \
npm run dev --prefix '$FRONTEND_DIR'"

# Create session with backend in the first pane
tmux new-session -d -s "$SESSION_NAME" -n "guard" "$BACKEND_CMD"

# Split horizontally (top/bottom) and run frontend in the bottom pane
tmux split-window -v -t "$SESSION_NAME:guard" "$FRONTEND_CMD"

# Select the top pane (backend) by default
tmux select-pane -t "$SESSION_NAME:guard.0"

# Add a status bar with useful info
tmux set-option -t "$SESSION_NAME" status on
tmux set-option -t "$SESSION_NAME" status-style "bg=colour235,fg=colour136"
tmux set-option -t "$SESSION_NAME" status-left "#[fg=colour46,bold] 🛡️ Ransomware Guard "
tmux set-option -t "$SESSION_NAME" status-right "#[fg=colour75] Backend :8000 | Frontend :5173 #[fg=colour240]| %H:%M "
tmux set-option -t "$SESSION_NAME" status-left-length 30
tmux set-option -t "$SESSION_NAME" status-right-length 50

echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Ransomware Guard tmux session started!${NC}"
echo -e "${GREEN}  Backend  → http://0.0.0.0:8000   (top pane)${NC}"
echo -e "${GREEN}  Frontend → http://localhost:5173  (bottom pane)${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}  Tmux cheatsheet:${NC}"
echo -e "    Ctrl+B ↑/↓    Switch between panes"
echo -e "    Ctrl+B d       Detach from session"
echo -e "    Ctrl+B z       Zoom into current pane"
echo -e "    Ctrl+C         Stop current service"
echo ""
echo -e "${YELLOW}  To reattach:${NC}  tmux attach -t $SESSION_NAME"
echo -e "${YELLOW}  To stop all:${NC}  tmux kill-session -t $SESSION_NAME"
echo ""

# Attach to the session
tmux attach-session -t "$SESSION_NAME"
