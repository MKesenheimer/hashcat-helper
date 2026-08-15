#!/bin/bash
#
# poll-status.sh — Query a running hashcat cracking session and output JSON status.
#
# Auto-detects the running hashcat session from the process list, then reads
# cracked.txt, hashes.hc22000, and crack.conf from the process's working directory.
# Falls back to session.log if no running sessions are found.
#
# Usage:
#   ./poll-status.sh              # auto-detects running session from process list
#   ./poll-status.sh -s <name>    # explicit session name
#   ./poll-status.sh -d <dir>     # override working directory (auto-detected by default)
#
# Output: JSON object with session info, progress, and GPU telemetry.

set -euo pipefail

SESSION_NAME=""
WORK_DIR="all"

while [[ $# -gt 0 ]]; do
  case $1 in
    -s|--session) SESSION_NAME="$2"; shift 2 ;;
    -d|--dir)     WORK_DIR="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [-s <session-name>] [-d <work-dir>]"
      exit 0
      ;;
    *) shift ;;
  esac
done

# Resolve work dir - default is the "all" directory next to this script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [[ "$WORK_DIR" != /* ]]; then
  WORK_DIR="$(cd "$SCRIPT_DIR/$WORK_DIR" 2>/dev/null && pwd)" || WORK_DIR="$SCRIPT_DIR/$WORK_DIR"
else
  WORK_DIR="$(cd "$WORK_DIR" 2>/dev/null && pwd)" || WORK_DIR="$WORK_DIR"
fi

# Determine session name
if [ -z "$SESSION_NAME" ]; then
  # Auto-detect running hashcat sessions from the process list
  SESSION_NAME=""
  if detected=$(pgrep -af "hashcat" 2>/dev/null | grep -- "--session" | sed 's/.*--session \([^ ]*\).*/\1/' | head -1); then
    SESSION_NAME="$detected"
  fi

  # Fall back to session.log only if no running sessions found
  if [ -z "$SESSION_NAME" ]; then
    SESSION_NAME="$(cat "${WORK_DIR}/session.log" 2>/dev/null)"
  fi

  if [ -z "$SESSION_NAME" ]; then
    echo '{"error":"no session name (set session.log or use -s)"}'
    exit 1
  fi
fi

# Auto-detect the working directory of the running hashcat process
# This ensures we read cracked.txt and hashes.hc22000 from the actual session dir
if [ -n "$SESSION_NAME" ]; then
  detected_pid=$(pgrep -af "hashcat" 2>/dev/null | awk -v sess="$SESSION_NAME" '
    index($0, "--session " sess) > 0 { print $1; exit }
  ')
  if [ -n "$detected_pid" ] && [ -d "/proc/$detected_pid/cwd" ] 2>/dev/null; then
    DETECTED_DIR=$(readlink -f "/proc/$detected_pid/cwd" 2>/dev/null || echo "")
    if [ -n "$DETECTED_DIR" ] && [ -f "${DETECTED_DIR}/crack.conf" ]; then
      WORK_DIR="$DETECTED_DIR"
    fi
  fi
fi

# Check if a hashcat process with this session name is running
# Use grep -F for fixed-string matching to handle special chars in session name
HASHCAT_PID=""
if hashcat_pid=$(pgrep -af "hashcat" 2>/dev/null | grep -F "hashcat" | grep -F "session" | grep -F "$SESSION_NAME" | head -1 | awk '{print $1}'); then
  if [ -n "$hashcat_pid" ] && kill -0 "$hashcat_pid" 2>/dev/null; then
    HASHCAT_PID="$hashcat_pid"
  fi
fi
IS_RUNNING=false
if [ -n "$HASHCAT_PID" ]; then
  IS_RUNNING=true
fi

# Parse session metadata from name: "prefix-stepN-wordlist+rule" or "prefix-stepN-wordlist"
SESSION_PRE=""
STEP_NUM=""
WORDLIST_BASE=""
RULE_BASE=""

if [[ "$SESSION_NAME" =~ ^(.+)-step([0-9]+)-(.+)$ ]]; then
  SESSION_PRE="${BASH_REMATCH[1]}"
  STEP_NUM="${BASH_REMATCH[2]}"
  REST="${BASH_REMATCH[3]}"
  # Split wordlist and rule on '+'
  if [[ "$REST" == *"+"* ]]; then
    WORDLIST_BASE="${REST%%+*}"
    RULE_BASE="+${REST#*+}"
  else
    WORDLIST_BASE="$REST"
    RULE_BASE=""
  fi
fi

# Count cracked passwords
CRACKED_COUNT=0
if [ -f "${WORK_DIR}/cracked.txt" ]; then
  CRACKED_COUNT=$(wc -l < "${WORK_DIR}/cracked.txt" 2>/dev/null || echo 0)
  CRACKED_COUNT=$(echo "$CRACKED_COUNT" | tr -d '[:space:]')
fi

# Get hash count from hashes.hc22000
HASH_COUNT=0
if [ -f "${WORK_DIR}/hashes.hc22000" ]; then
  HASH_COUNT=$(wc -l < "${WORK_DIR}/hashes.hc22000" 2>/dev/null || echo 0)
  HASH_COUNT=$(echo "$HASH_COUNT" | tr -d '[:space:]')
  # Hash files have 1 line per unique hash (duplicates removed by hashcat)
fi

# Calculate progress percentage
PROGRESS_PCT="0"
if [ "$HASH_COUNT" -gt 0 ] 2>/dev/null; then
  PROGRESS_PCT=$(python3 -c "print(round(${CRACKED_COUNT}/${HASH_COUNT}*100, 2))" 2>/dev/null || echo "0")
fi

# Count total steps from config
TOTAL_STEPS=0
if [ -f "${WORK_DIR}/crack.conf" ]; then
  TOTAL_STEPS=$(grep -c '^\[step' "${WORK_DIR}/crack.conf" 2>/dev/null || echo 0)
  TOTAL_STEPS=$(echo "$TOTAL_STEPS" | tr -d '[:space:]')
fi

# Gather GPU data
GPU_JSON="[]"
GPU_DATA=$(python3 - <<'PYEOF'
import json, subprocess, os, glob, time
from datetime import timedelta as dt_timedelta

gpus = []

# Map DRM card numbers to ROCm indices
# card1 = ROCm GPU[0], card2 = GPU[1], etc.
# Only process cards with AMD vendor
for card_num in range(1, 6):
    dev_path = f"/sys/class/drm/card{card_num}/device"
    if not os.path.isdir(dev_path):
        continue

    # Check vendor (0x1002 = AMD)
    try:
        vendor = open(f"{dev_path}/vendor").read().strip()
    except:
        continue
    if vendor != "0x1002":
        continue

    # GPU busy percentage
    try:
        busy = int(open(f"{dev_path}/gpu_busy_percent").read().strip().rstrip('%'))
    except:
        busy = None

    # Temperature
    temp = None
    hwmon_dirs = glob.glob(f"{dev_path}/hwmon/hwmon*")
    for hwmon in hwmon_dirs:
        try:
            temp_file = glob.glob(f"{hwmon}/temp*_input")
            if temp_file:
                temp_raw = open(temp_file[0]).read().strip()
                temp = int(temp_raw) // 1000  # mC to C
                break
        except:
            continue

    # GPU name from PCI ID mapping
    # Note: dev_path already points to /sys/class/drm/cardX/device/
    # The vendor/device ID files are directly under dev_path, not under dev_path/device
    gpu_name = "Unknown"
    try:
        vendor_hex = open(f"{dev_path}/vendor").read().strip()
        device_hex = open(f"{dev_path}/device").read().strip()
        pci_str = f"{vendor_hex}:{device_hex}"
        # Known AMD GPU device IDs
        gpu_ids = {
            "0x1002:0x73ff": "AMD Radeon RX 6600",
            "0x1002:0x73ef": "AMD Radeon RX 6600 XT",
            "0x1002:0x744c": "AMD Radeon RX 7900 XT",
            "0x1002:0x744e": "AMD Radeon RX 7900 XTX",
            "0x1002:0x67df": "AMD Radeon RX 6700 XT",
            "0x1002:0x6710": "AMD Radeon RX 6800",
            "0x1002:0x68af": "AMD Radeon RX 6800 XT",
            "0x1002:0x764e": "AMD Radeon RX 7600",
        }
        gpu_name = gpu_ids.get(pci_str, f"AMD GPU ({pci_str})")
    except:
        pass

    # ROCm index (card1 -> 0, card2 -> 1, etc.)
    rocm_index = card_num - 1

    gpus.append({
        "index": rocm_index,
        "drm_card": card_num,
        "name": gpu_name,
        "utilization": busy,
        "temperature_c": temp,
    })

# Get power data from rocm-smi
try:
    result = subprocess.run(
        ["rocm-smi", "--alldevices", "-P"],
        capture_output=True, text=True, timeout=10
    )
    # Parse power lines: "GPU[X] : Average Graphics Package Power (W): YYY.Y"
    lines = result.stdout.split('\n')
    gpu_powers = {}
    for line in lines:
        if 'Average Graphics Package Power' in line:
            parts = line.split(':')
            if len(parts) >= 2:
                gpu_label = parts[0].strip()  # "GPU[0] "
                power_str = parts[-1].strip()  # "100.0"
                try:
                    gpu_idx = int(gpu_label.replace('GPU[', '').rstrip(']'))
                    gpu_powers[gpu_idx] = float(power_str)
                except ValueError:
                    pass

    for gpu in gpus:
        if gpu["index"] in gpu_powers:
            gpu["power_draw_w"] = gpu_powers[gpu["index"]]
except:
    pass  # rocm-smi may not be available

print(json.dumps(gpus))
PYEOF
)

# Build status timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")

# Output JSON
python3 - "$IS_RUNNING" "$SESSION_NAME" "$SESSION_PRE" "$STEP_NUM" "$TOTAL_STEPS" "$HASH_COUNT" "$CRACKED_COUNT" "$PROGRESS_PCT" "$WORDLIST_BASE" "$RULE_BASE" "$HASHCAT_PID" "$GPU_DATA" "$TIMESTAMP" <<'PYEOF'
import json, os, sys
import time
from datetime import timedelta

is_running = sys.argv[1] == "true"
session_name = sys.argv[2]
session_pre = sys.argv[3]
step_num = sys.argv[4]
total_steps = int(sys.argv[5]) if sys.argv[5] else 0
hash_count = int(sys.argv[6]) if sys.argv[6] else 0
cracked_count = int(sys.argv[7]) if sys.argv[7] else 0
progress_pct = float(sys.argv[8]) if sys.argv[8] else 0
wordlist_base = sys.argv[9]
rule_base = sys.argv[10]
hashcat_pid = sys.argv[11]
gpu_json_str = sys.argv[12]
timestamp = sys.argv[13]

gpus = json.loads(gpu_json_str) if gpu_json_str != "[]" else []

# Calculate elapsed time if hashcat is running
elapsed_seconds = 0
elapsed_human = "0:00:00"
remaining_human = "?"
speed_str = ""
speed_raw = 0

if is_running and hashcat_pid:
    # Try to find when hashcat started by checking its /proc
    try:
        starttime = open(f"/proc/{hashcat_pid}/stat").read().split()[21]
        clk_tck = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
        # Get system boot time + uptime
        boot_time = open("/proc/stat").read().split('\n')[0]
        # Actually, easier: check the session restore file modification time
        restore_path = f"/home/kesenheimer/.local/share/hashcat/sessions/{session_name}.restore"
        if os.path.exists(restore_path):
            mtime = os.path.getmtime(restore_path)
            elapsed_seconds = int(time.time() - mtime)
            elapsed_human = str(timedelta(seconds=elapsed_seconds))
    except:
        pass

    # Try to estimate speed from GPU utilization changes
    # This is a rough heuristic: if GPUs are at ~100% utilization, they're hashing fast
    active_gpus = [g for g in gpus if g.get("utilization") is not None and g["utilization"] > 50]
    if active_gpus:
        avg_util = sum(g["utilization"] for g in active_gpus) / len(active_gpus)
        if avg_util > 80:
            speed_str = "active"
        elif avg_util > 30:
            speed_str = "reduced"
        else:
            speed_str = "idle"

result = {
    "session": session_name,
    "session_pre": session_pre,
    "step": int(step_num) if step_num and step_num.isdigit() else 0,
    "total_steps": total_steps,
    "wordlist": wordlist_base,
    "rule": rule_base,
    "status": "running" if is_running else "stopped",
    "hashcat_pid": int(hashcat_pid) if hashcat_pid else None,
    "hash_count": hash_count,
    "cracked_count": cracked_count,
    "progress_percent": progress_pct,
    "elapsed_seconds": elapsed_seconds,
    "elapsed_human": elapsed_human,
    "remaining_human": remaining_human,
    "speed": speed_str,
    "gpus": gpus,
    "timestamp": timestamp
}

print(json.dumps(result, indent=2))
PYEOF
