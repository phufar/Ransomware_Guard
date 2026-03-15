#!/usr/bin/env bash
# Helper: runs in the FRONTEND pane (bottom-left)
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

clear
echo -e "${GREEN}${BOLD}═══════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}     FRONTEND  (vite :5173)${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════${NC}"
echo ""
npm run dev --prefix "$SCRIPT_DIR/frontend"
