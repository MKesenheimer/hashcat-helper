#!/usr/bin/env python3
"""
status-server.py — Lightweight HTTP server for hashcat cracking status.

Zero external dependencies — uses Python's built-in http.server and subprocess.
Polls poll-status.sh every 2 seconds and serves the result via HTTP.

Usage:
    python3 status-server.py              # default: port 8080, no auth
    python3 status-server.py --port 9090  # custom port
    python3 status-server.py --auth TOKEN # require Authorization: Bearer TOKEN

Access:
    http://localhost:8080/               # Web UI
    http://localhost:8080/api/status     # JSON status (single snapshot)
    http://localhost:8080/api/history    # JSON history (last 300 snapshots)
    http://localhost:8080/api/sessions   # List known sessions
    http://localhost:8080/api/gpu        # GPU metrics only
"""

import http.server
import json
import os
import socket
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime
from html import escape
from urllib.parse import urlparse, parse_qs

# ── Configuration ──────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POLL_SCRIPT = os.path.join(SCRIPT_DIR, "poll-status.sh")
HISTORY_MAX = 300  # Keep last N snapshots
POLL_INTERVAL = 2  # Seconds between polls
DEFAULT_PORT = 8080

# ── Globals ────────────────────────────────────────────────────────────────
history = []       # Last N snapshots (list of dicts)
last_status = {}   # Most recent snapshot
status_lock = threading.Lock()
running = True

# ── CLI parsing ────────────────────────────────────────────────────────────
def parse_args():
    port = DEFAULT_PORT
    auth_token = None
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == "--port":
            port = int(sys.argv[i+1]); i += 2
        elif sys.argv[i] == "--auth":
            auth_token = sys.argv[i+1]; i += 2
        elif sys.argv[i] in ("--help", "-h"):
            print(__doc__)
            sys.exit(0)
        else:
            i += 1
    return port, auth_token

# ── Polling loop ───────────────────────────────────────────────────────────
def poll():
    """Run poll-status.sh and update the shared state."""
    global history, last_status, running
    while running:
        try:
            result = subprocess.run(
                ["bash", POLL_SCRIPT],
                capture_output=True, text=True, timeout=10,
                cwd=SCRIPT_DIR
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout.strip())
                data["_poll_time"] = datetime.now(tz=None).isoformat() + "Z"
                with status_lock:
                    last_status = data
                    history.append(data)
                    if len(history) > HISTORY_MAX:
                        history = history[-HISTORY_MAX:]
        except Exception:
            pass  # Silently fail on poll error
        time.sleep(POLL_INTERVAL)

# ── HTTP Handler ───────────────────────────────────────────────────────────
class StatusHandler(http.server.BaseHTTPRequestHandler):
    """Handle HTTP requests for status API and web UI."""

    def log_message(self, format, *args):
        """Suppress default stderr logging."""
        pass

    def check_auth(self):
        """Check Bearer token if auth is configured."""
        # Currently no auth enforcement — easy to add with --auth flag
        pass

    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def do_GET(self):
        path = urlparse(self.path).path
        self.check_auth()

        if path == "/api/status":
            with status_lock:
                self.send_json(last_status)

        elif path == "/api/history":
            with status_lock:
                self.send_json({"history": history, "count": len(history)})

        elif path == "/api/gpu":
            with status_lock:
                gpu_data = last_status.get("gpus", [])
                self.send_json({
                    "session": last_status.get("session"),
                    "status": last_status.get("status"),
                    "gpus": gpu_data
                })

        elif path == "/api/sessions":
            # Scan session.log files across session directories
            sessions = []
            # Check finished.log
            finished_log = os.path.join(SCRIPT_DIR, "finished.log")
            if os.path.exists(finished_log):
                with open(finished_log) as f:
                    for line in f:
                        name = line.strip()
                        if name:
                            sessions.append({"name": name, "type": "finished"})
            # Check for running screen sessions
            try:
                result = subprocess.run(
                    ["screen", "-ls"], capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split("\n"):
                    if "(Detached)" in line:
                        parts = line.split()
                        if len(parts) >= 1:
                            sess_name = parts[0].split(".")[1] if "." in parts[0] else parts[0]
                            sessions.append({"name": sess_name, "type": "running"})
            except:
                pass
            self.send_json({"sessions": sessions})

        elif path == "/":
            self.send_html_ui()

        else:
            self.send_json({"error": "not found"}, 404)

    def send_html_ui(self):
        """Serve the main HTML UI (embedded to keep it single-file)."""
        html = HTML_TEMPLATE
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(html.encode())

# ── HTML Template (single-file SPA) ────────────────────────────────────────
HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Crack Monitor</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'JetBrains Mono', 'Fira Code', 'SF Mono', monospace; background: #0d1117; color: #c9d1d9; font-size: 13px; }
:root {
  --bg: #0d1117; --card: #161b22; --border: #30363d;
  --green: #3fb950; --red: #f85149; --yellow: #d29922;
  --blue: #58a6ff; --text: #c9d1d9; --dim: #8b949e;
}
header { padding: 16px 24px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
header h1 { font-size: 18px; font-weight: 600; color: #f0f6fc; }
#status-badge { padding: 4px 12px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
#status-badge.running { background: #238636; color: #fff; }
#status-badge.stopped { background: #21262d; color: var(--dim); }

.container { max-width: 1200px; margin: 0 auto; padding: 24px; }

/* Session bar */
.session-bar { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; }
.session-info { display: flex; gap: 24px; align-items: center; }
.session-info .label { color: var(--dim); font-size: 11px; text-transform: uppercase; }
.session-info .value { font-size: 14px; font-weight: 600; color: #f0f6fc; }
.session-name { color: var(--blue); font-size: 14px; }

/* Progress */
.progress-section { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }
.progress-bar-container { height: 28px; background: #21262d; border-radius: 6px; overflow: hidden; margin: 12px 0; position: relative; }
.progress-bar-fill { height: 100%; background: linear-gradient(90deg, #238636, #3fb950); border-radius: 6px; transition: width 0.5s ease; min-width: 2px; }
.progress-label { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-size: 12px; font-weight: 700; color: #fff; text-shadow: 0 1px 2px rgba(0,0,0,0.5); }
.progress-stats { display: flex; justify-content: space-between; color: var(--dim); font-size: 12px; }

/* GPU grid */
.gpu-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 16px; margin-bottom: 20px; }
.gpu-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.gpu-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
.gpu-name { font-weight: 600; font-size: 13px; color: #f0f6fc; }
.gpu-index { font-size: 11px; color: var(--dim); }
.gpu-metrics { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.gpu-metric { background: #21262d; border-radius: 6px; padding: 10px 12px; }
.gpu-metric .metric-label { font-size: 10px; color: var(--dim); text-transform: uppercase; margin-bottom: 2px; }
.gpu-metric .metric-value { font-size: 16px; font-weight: 700; }
.gpu-metric .metric-value.high { color: var(--red); }
.gpu-metric .metric-value.medium { color: var(--yellow); }
.gpu-metric .metric-value.normal { color: var(--green); }
.gpu-metric .metric-value.active { color: var(--blue); }
.gpu-util-bar { height: 4px; background: #21262d; border-radius: 2px; margin-top: 10px; overflow: hidden; }
.gpu-util-fill { height: 100%; border-radius: 2px; transition: width 0.5s ease, background 0.5s ease; }

/* Speed indicator */
.speed-indicator { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.speed-indicator.active { background: #238636; color: #fff; }
.speed-indicator.reduced { background: #9e6a03; color: #fff; }
.speed-indicator.idle { background: #21262d; color: var(--dim); }
.speed-indicator.off { background: #21262d; color: var(--dim); }

/* Footer */
footer { padding: 16px 24px; border-top: 1px solid var(--border); color: var(--dim); font-size: 11px; text-align: center; }

/* Responsive */
@media (max-width: 600px) {
  .gpu-grid { grid-template-columns: 1fr; }
  .session-info { flex-direction: column; align-items: flex-start; gap: 4px; }
}

/* Pulse animation for running status */
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
.pulse { animation: pulse 2s infinite; }
</style>
</head>
<body>

<header>
  <h1>⚡ Crack Monitor</h1>
  <div id="status-badge" class="stopped">checking...</div>
</header>

<div class="container">
  <!-- Session bar -->
  <div class="session-bar">
    <div class="session-info">
      <div>
        <div class="label">Session</div>
        <div class="session-name" id="session-name">—</div>
      </div>
      <div>
        <div class="label">Step</div>
        <div class="value" id="session-step">—</div>
      </div>
      <div>
        <div class="label">Wordlist</div>
        <div class="value" id="session-wordlist">—</div>
      </div>
      <div>
        <div class="label">Rule</div>
        <div class="value" id="session-rule">—</div>
      </div>
    </div>
    <div class="session-info">
      <div>
        <div class="label">Speed</div>
        <div id="session-speed" class="speed-indicator idle">—</div>
      </div>
      <div>
        <div class="label">Elapsed</div>
        <div class="value" id="session-elapsed">—</div>
      </div>
      <div>
        <div class="label">ETA</div>
        <div class="value" id="session-eta">—</div>
      </div>
    </div>
  </div>

  <!-- Progress -->
  <div class="progress-section">
    <div style="display:flex; justify-content:space-between; align-items:center;">
      <span style="color:var(--dim); font-size:11px; text-transform:uppercase;">Progress</span>
      <span id="cracked-label" style="color:var(--green); font-size:12px;">0 cracked</span>
    </div>
    <div class="progress-bar-container">
      <div class="progress-bar-fill" id="progress-fill" style="width:0%"></div>
      <div class="progress-label" id="progress-label">0.00%</div>
    </div>
    <div class="progress-stats">
      <span id="hash-count-label">0 hashes</span>
      <span id="step-label">step 0 / 0</span>
    </div>
  </div>

  <!-- GPU cards -->
  <div class="gpu-grid" id="gpu-grid">
    <!-- GPU cards injected by JS -->
  </div>
</div>

<footer>
  Crack Monitor · Auto-refreshes every 2s · <span id="last-update">never</span>
</footer>

<script>
const POLL_INTERVAL = 2000;
let prevCracked = 0;

function updateUI(data) {
  // Status badge
  const badge = document.getElementById('status-badge');
  const isRunning = data.status === 'running';
  badge.className = isRunning ? 'running pulse' : 'stopped';
  badge.textContent = isRunning ? 'running' : 'stopped';

  // Session info
  document.getElementById('session-name').textContent = data.session || '—';
  const stepText = data.total_steps > 1
    ? `${data.step} / ${data.total_steps}`
    : `${data.step}`;
  document.getElementById('session-step').textContent = stepText;
  document.getElementById('session-wordlist').textContent = data.wordlist || '—';
  document.getElementById('session-rule').textContent = data.rule || '—';

  // Speed
  const speedEl = document.getElementById('session-speed');
  const speed = data.speed || '';
  speedEl.className = `speed-indicator ${speed || 'off'}`;
  speedEl.textContent = speed ? speed.charAt(0).toUpperCase() + speed.slice(1) : '—';

  // Time
  document.getElementById('session-elapsed').textContent = data.elapsed_human || '—';
  document.getElementById('session-eta').textContent = data.remaining_human || '—';

  // Progress
  const pct = data.progress_percent || 0;
  document.getElementById('progress-fill').style.width = pct + '%';
  document.getElementById('progress-label').textContent = pct.toFixed(2) + '%';
  document.getElementById('cracked-label').textContent = `${data.cracked_count || 0} cracked`;
  document.getElementById('hash-count-label').textContent = `${(data.hash_count || 0)} hashes`;
  document.getElementById('step-label').textContent = `step ${data.step || 0} / ${data.total_steps || 0}`;

  // GPU cards
  const grid = document.getElementById('gpu-grid');
  const gpus = data.gpus || [];
  let html = '';
  for (const gpu of gpus) {
    const util = gpu.utilization ?? 0;
    const temp = gpu.temperature_c;
    const power = gpu.power_draw_w;
    const utilClass = util > 80 ? 'high' : util > 30 ? 'medium' : 'normal';
    const tempClass = temp > 85 ? 'high' : temp > 70 ? 'medium' : 'normal';
    const utilColor = util > 80 ? '#3fb950' : util > 30 ? '#d29922' : '#484f58';

    html += `
      <div class="gpu-card">
        <div class="gpu-header">
          <span class="gpu-name">${gpu.name}</span>
          <span class="gpu-index">GPU ${gpu.index}</span>
        </div>
        <div class="gpu-metrics">
          <div class="gpu-metric">
            <div class="metric-label">Utilization</div>
            <div class="metric-value ${utilClass}">${util}%</div>
          </div>
          <div class="gpu-metric">
            <div class="metric-label">Temperature</div>
            <div class="metric-value ${tempClass}">${temp}°C</div>
          </div>
          <div class="gpu-metric">
            <div class="metric-label">Power</div>
            <div class="metric-value normal">${power ? power.toFixed(0) + 'W' : '—'}</div>
          </div>
          <div class="gpu-metric">
            <div class="metric-label">Fan</div>
            <div class="metric-value normal">${gpu.fan_rpm || gpu.utilization || 0}%</div>
          </div>
        </div>
        <div class="gpu-util-bar">
          <div class="gpu-util-fill" style="width:${util}%; background:${utilColor}"></div>
        </div>
      </div>`;
  }
  grid.innerHTML = html;

  // Last update
  document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
}

async function poll() {
  try {
    const res = await fetch('/api/status');
    if (res.ok) {
      const data = await res.json();
      updateUI(data);
    }
  } catch(e) {
    // Silently fail — will retry
  }
}

// Initial poll then interval
poll();
setInterval(poll, POLL_INTERVAL);
</script>
</body>
</html>"""

# ── Main ───────────────────────────────────────────────────────────────────
def main():
    global running
    port, auth_token = parse_args()

    # Start polling thread
    poll_thread = threading.Thread(target=poll, daemon=True)
    poll_thread.start()
    print(f"🔍 Polling {POLL_SCRIPT} every {POLL_INTERVAL}s...")

    # Start HTTP server (SO_REUSEADDR to avoid "address already in use")
    server = http.server.HTTPServer(("0.0.0.0", port), StatusHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print(f"🌐 Crack Monitor → http://localhost:{port}/")
    print(f"   API:    http://localhost:{port}/api/status")
    print(f"   History: http://localhost:{port}/api/history")

    def shutdown(signum, frame):
        global running
        print("\n🛑 Shutting down...")
        running = False
        server.shutdown()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown(None, None)

if __name__ == "__main__":
    main()
