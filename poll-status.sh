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

# Get power and utilization data from rocm-smi
# (sysfs gpu_busy_percent is unreliable on AMD; rocm-smi is accurate)
try:
    result = subprocess.run(
        ["rocm-smi", "--alldevices", "-P", "--showuse"],
        capture_output=True, text=True, timeout=10
    )
    # Parse power lines: "GPU[X] : Average Graphics Package Power (W): YYY.Y"
    # and utilization lines: "GPU[X] : GPU use (%): YY"
    lines = result.stdout.split('\n')
    gpu_powers = {}
    gpu_utils = {}
    for line in lines:
        if 'Average Graphics Package Power' in line or 'GPU use (%)' in line:
            parts = line.split(':')
            if len(parts) >= 2:
                gpu_label = parts[0].strip()  # "GPU[0] "
                value_str = parts[-1].strip()
                try:
                    gpu_idx = int(gpu_label.replace('GPU[', '').rstrip(']'))
                    if 'GPU use (%)' in line:
                        gpu_utils[gpu_idx] = int(value_str)
                    else:
                        gpu_powers[gpu_idx] = float(value_str)
                except ValueError:
                    pass

    for gpu in gpus:
        if gpu["index"] in gpu_powers:
            gpu["power_draw_w"] = gpu_powers[gpu["index"]]
        if gpu["index"] in gpu_utils:
            gpu["utilization"] = gpu_utils[gpu["index"]]
except:
    pass  # rocm-smi may not be available

print(json.dumps(gpus))
PYEOF
)

# Build status timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")

# Output JSON
python3 - "$IS_RUNNING" "$SESSION_NAME" "$SESSION_PRE" "$STEP_NUM" "$TOTAL_STEPS" "$HASH_COUNT" "$CRACKED_COUNT" "$PROGRESS_PCT" "$WORDLIST_BASE" "$RULE_BASE" "$HASHCAT_PID" "$GPU_DATA" "$TIMESTAMP" <<'PYEOF'
import json, os, re, subprocess, sys, time
from datetime import datetime

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


def fmt_duration(secs):
    secs = max(0, int(secs))
    if secs == 0:
        return "—"
    d, r = divmod(secs, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def parse_hc_datetime(s):
    """Parse a hashcat absolute datetime like 'Wed Aug 26 14:37:42 2026'."""
    m = re.match(r"[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})", s or "")
    if not m:
        return None
    months = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
              "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
    mon = months.get(m.group(1))
    if not mon:
        return None
    try:
        return datetime(int(m.group(6)), mon, int(m.group(2)),
                        int(m.group(3)), int(m.group(4)), int(m.group(5)))
    except ValueError:
        return None


def find_screen_session(pid):
    """Return the PID of the screen session that is an ancestor of pid, if any."""
    parents = {}
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            with open(f"/proc/{p}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            parents[int(p)] = int(fields[1])
        except (OSError, IndexError, ValueError):
            continue
    try:
        out = subprocess.run(["screen", "-ls"], capture_output=True, text=True,
                             timeout=5).stdout
    except Exception:
        return None
    for m in re.finditer(r"^\s*(\d+)\.\S+", out, re.M):
        spid = int(m.group(1))
        stack, seen = [spid], set()
        while stack:
            cur = stack.pop()
            if cur == pid:
                return spid
            if cur in seen:
                continue
            seen.add(cur)
            for k, v in parents.items():
                if v == cur:
                    stack.append(k)
    return None


def has_status_flag(pid):
    """True if hashcat was started with --status (periodic blocks on its own)."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return b"--status" in f.read()
    except OSError:
        return False


def _dbg(*args):
    if os.environ.get("HC_DEBUG"):
        print("[hc-debug]", *args, file=sys.stderr)


def hardcopy_and_parse(screen_pid):
    """Dump the screen (scrollback + display) and parse the newest complete
    status block belonging to our session. Returns None if there is none.

    A fully rendered block ends with its Hardware.Mon line(s). If hashcat is
    still writing the newest block, we retry once, then fall back to the
    previous complete block of our session."""
    def dump():
        try:
            r = subprocess.run(["screen", "-X", "-S", str(screen_pid), "hardcopy", "-h", HC_TMP],
                               capture_output=True, timeout=3)
            with open(HC_TMP) as f:
                text = f.read()
            _dbg(f"hardcopy: rc={r.returncode} len={len(text)}")
            return text
        except Exception as e:
            _dbg(f"hardcopy exception: {e!r}")
            return ""

    def starts_of(t):
        return [m.start() for m in re.finditer(r"^Session\.{5,}: ", t, re.M)]

    def complete(blk):
        # Hardware.Mon = last data line of a GPU block; Recovered covers
        # host-only sessions that have no Hardware.Mon lines.
        return "Hardware.Mon" in blk or "Recovered" in blk

    # 'screen -X hardcopy' can return before the file is fully written,
    # so retry until the dump looks complete.
    text = ""
    for _ in range(3):
        text = dump()
        if text and ("[s]tatus" in text or "Session" in text):
            break
        time.sleep(0.3)
    if not text:
        return None

    starts = starts_of(text)
    if not starts:
        _dbg("no Session block found in hardcopy")
        return None
    # Newest block still being written by hashcat (no tail line yet):
    # give it a moment, then dump once more.
    if not complete(text[starts[-1]:]):
        time.sleep(0.4)
        text = dump() or text
        starts = starts_of(text) or starts
    if not starts:
        return None

    # Walk from newest to oldest: first complete block of our session.
    for i in range(len(starts) - 1, -1, -1):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        block = text[starts[i]:end]
        m = re.search(r"^Session\.{5,}: (\S+)", block, re.M)
        if not m or m.group(1) != session_name:
            continue
        if i == len(starts) - 1 and not complete(block):
            _dbg("newest block incomplete (hashcat mid-write), using previous block")
            continue

        def grab(pat):
            mm = re.search(pat, block, re.M)
            return mm.group(1).strip() if mm else None

        info = {
            "status": grab(r"^Status\.{2,}: (\S+)"),
            "time_started": grab(r"^Time\.Started\.{2,}: (.+)"),
            "time_estimated": grab(r"^Time\.Estimated\.{2,}: (.+)"),
            "speed": grab(r"^Speed\.#\*\.{2,}: (.+)"),
        }
        # Overlay fan speed from the block onto the GPU list (only source for
        # it; utilization/temperature come from rocm-smi/sysfs, which are
        # fresher). hashcat device #NN: OpenCL 5-8 -> GPU 0-3, HIP 1-4 -> 0-3
        for hm in re.finditer(r"^Hardware\.Mon\.#(\d+)\.{1,}: Temp:\s*(\d+)c Fan:\s*(\d+)% Util:\s*(\d+)%",
                              block, re.M):
            dev = int(hm.group(1))
            idx = dev - 5 if dev >= 5 else dev - 1
            for g in gpus:
                if g.get("index") == idx:
                    g["fan_percent"] = int(hm.group(3))
                    break
        return info
    _dbg(f"no complete block for session {session_name!r}")
    return None


# ── Elapsed time: runtime of the current hashcat process (from /proc) ──
elapsed_seconds = 0
if is_running and hashcat_pid:
    try:
        with open(f"/proc/{hashcat_pid}/stat") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        starttime_ticks = int(fields[19])  # field 22 of /proc/PID/stat
        clk_tck = os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])
        elapsed_seconds = max(0, int(uptime - starttime_ticks / clk_tck))
    except (OSError, IndexError, ValueError):
        pass

# ── ETA, speed and GPU telemetry from the newest hashcat status block ──
HC_TMP = "/tmp/.hc-status-hardcopy"
try:  # remove hardcopy left behind by a poller killed mid-run
    os.unlink(HC_TMP)
except OSError:
    pass

remaining_human = "—"
speed_str = ""
hashcat_status = ""
if is_running and hashcat_pid:
    try:
        screen_pid = find_screen_session(int(hashcat_pid))
        block = hardcopy_and_parse(screen_pid) if screen_pid else None
        # Press 's' to force a status block when there is none on screen, and
        # periodically for sessions started without --status (their blocks go
        # stale otherwise). Throttled via a timestamp file.
        if screen_pid and (block is None or not has_status_flag(int(hashcat_pid))):
            ts_path = "/tmp/.hc-status-stuff-ts"
            try:
                with open(ts_path) as f:
                    last_stuff = float(f.read().strip() or 0)
            except (OSError, ValueError):
                last_stuff = 0.0
            now = time.time()
            interval = 10 if block is None else 300
            if now - last_stuff > interval:
                with open(ts_path, "w") as f:
                    f.write(str(now))
                subprocess.run(["screen", "-X", "-S", str(screen_pid),
                                "stuff", "s"], capture_output=True, timeout=5)
                time.sleep(1.5)
                block = hardcopy_and_parse(screen_pid)
    except Exception as e:
        _dbg(f"eta section exception: {e!r}")
        block = None

    if block:
        hashcat_status = block.get("status") or ""
        speed_str = block.get("speed") or ""
        est_dt = parse_hc_datetime(block.get("time_estimated"))
        if est_dt:
            remaining = int((est_dt - datetime.now()).total_seconds())
            remaining_human = fmt_duration(remaining) if remaining > 0 else "0s"

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
    "elapsed_human": fmt_duration(elapsed_seconds) if elapsed_seconds else "—",
    "remaining_human": remaining_human,
    "speed": speed_str,
    "hashcat_status": hashcat_status,
    "gpus": gpus,
    "timestamp": timestamp
}

print(json.dumps(result, indent=2))
PYEOF
