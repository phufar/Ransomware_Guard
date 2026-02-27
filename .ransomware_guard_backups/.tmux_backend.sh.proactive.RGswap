#!/usr/bin/env bash
# Helper: runs in the BACKEND pane (right, full height)
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

clear
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  🛡️  BACKEND  (uvicorn :8000)${NC}"
echo -e "${GREEN}${BOLD}══════════════════════════════════════════════${NC}"
echo ""
source "$SCRIPT_DIR/backend/.venv/bin/activate"
sudo "$SCRIPT_DIR/backend/.venv/bin/python" -m uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload \
    --app-dir "$SCRIPT_DIR/backend"
