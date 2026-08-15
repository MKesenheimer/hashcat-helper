#!/bin/bash
#
# start-status-server.sh — Launch the hashcat status web server.
#
# Usage:
#   ./start-status-server.sh              # runs in background screen
#   ./start-status-server.sh --stop       # stop the server
#   ./start-status-server.sh --fg         # runs in foreground
#   ./start-status-server.sh --port 9090  # custom port

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVER_SCRIPT="$SCRIPT_DIR/status-server.py"
SCREEN_NAME="crack-status"

PORT=""
FG=false
STOP=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --fg)    FG=true; shift ;;
    --stop)  STOP=true; shift ;;
    --port)  PORT="-p $2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--stop] [--fg] [--port PORT]"
      exit 0
      ;;
    *) shift ;;
  esac
done

if $STOP; then
  if screen -ls 2>/dev/null | grep -q "$SCREEN_NAME"; then
    screen -S "$SCREEN_NAME" -X quit
    echo "Server stopped."
  else
    echo "Server not running."
  fi
  exit 0
fi

if $FG; then
  echo "Starting crack-status server in foreground..."
  python3 "$SERVER_SCRIPT" $PORT
else
  # Check if already running
  if screen -ls 2>/dev/null | grep -q "$SCREEN_NAME"; then
    echo "Server already running in screen session '$SCREEN_NAME'"
    echo "Attach: screen -r $SCREEN_NAME"
    echo "Stop:   ./start-status-server.sh --stop"
    exit 0
  fi

  echo "Starting crack-status server in background..."
  screen -dmS "$SCREEN_NAME" bash -c "
    cd '$SCRIPT_DIR'
    python3 '$SERVER_SCRIPT' $PORT
  "
  sleep 1
  echo "Server started. Open http://localhost:8080/ in your browser."
  echo "Attach: screen -r $SCREEN_NAME"
  echo "Stop:   ./start-status-server.sh --stop"
fi
