#!/usr/bin/env bash
# Helper: runs in the STATUS pane (top-left)
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

clear
echo -e "${GREEN}${BOLD}═══════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  🛡️  RANSOMWARE GUARD  ─  STATUS${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════${NC}"
echo ""
echo -e "${CYAN}  Session :${NC}  ransomware-guard"
echo -e "${CYAN}  Backend :${NC}  http://0.0.0.0:8000"
echo -e "${CYAN}  Frontend:${NC}  http://localhost:5173"
echo ""
echo -e "${CYAN}  Tmux Controls:${NC}"
echo "    Ctrl+B ←/→/↑/↓  Switch panes"
echo "    Ctrl+B z         Zoom pane (toggle)"
echo "    Ctrl+B d         Detach session"
echo ""
echo -e "${CYAN}  Session Controls:${NC}"
echo "    tmux attach -t ransomware-guard"
echo "    tmux kill-session -t ransomware-guard"
echo ""
echo -e "${GREEN}──────────────────────────────────${NC}"
echo -e "${CYAN}  Live Status:${NC}"
echo ""

while true; do
    BACKEND_UP=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/api/status 2>/dev/null || echo '000')
    FRONTEND_UP=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:5173 2>/dev/null || echo '000')

    if [ "$BACKEND_UP" = "000" ]; then
        BE_STATUS="${RED}● OFFLINE${NC}"
    else
        BE_STATUS="${GREEN}● ONLINE${NC}  (HTTP $BACKEND_UP)"
    fi

    if [ "$FRONTEND_UP" = "000" ]; then
        FE_STATUS="${RED}● OFFLINE${NC}"
    else
        FE_STATUS="${GREEN}● ONLINE${NC}  (HTTP $FRONTEND_UP)"
    fi

    echo -ne "\r  Backend: $BE_STATUS  |  Frontend: $FE_STATUS     "
    sleep 5
done
