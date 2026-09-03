#!/usr/bin/env python3
"""Upload password hashes to a remote server via SCP/SSH and start cracking.

Copies all hash files (md5.txt, md5_salt.txt, bcrypt.txt, argon2.txt, pbkdf2.txt)
and the crack configuration file to a user-specified directory on the remote server.
Then starts a cracking session via ssh by executing ./crack.sh with the provided
arguments.

Authentication is done via SSH key (no password needed).

Usage examples:
    # All defaults (server=hashcat, user=kesenheimer, target dir, config & session names):
    python3 upload_and_crack.py

    # Custom server IP:
    python3 upload_and_crack.py --server 192.168.1.100

    # Custom everything:
    python3 upload_and_crack.py \
        --server cracking.example.com \
        --user kesenheimer \
        --target /home/kesenheimer/Desktop/cracking/recent \
        --config crack.conf \
        --session run-01 \
        --devices 5,6,7,8

Requirements:
    - SSH key-based authentication configured (e.g. in ~/.ssh/config or default key)
    - scp and ssh available in PATH
    - ./crack.sh exists at the remote target directory
    - Hash files (*.txt) and crack config (.conf) exist locally
"""
import argparse
import os
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
HASH_FILES = ["md5.txt", "md5_salt.txt", "bcrypt.txt", "argon2.txt", "pbkdf2.txt"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def check_ssh_key():
    """Verify that an SSH key is available for key-based auth."""
    key_paths = [
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.ssh/id_ed25519"),
        os.path.expanduser("~/.ssh/id_ecdsa"),
        os.path.expanduser("~/.ssh/id_dsa"),
    ]
    for kp in key_paths:
        if os.path.isfile(kp):
            return kp
    return None

def run_command(
    cmd: list[str],
    description: str,
    capture: bool = False,
    timeout: int | None = 120,
) -> str | None:
    """Run a shell command and print its output. Raises on failure."""
    print(f"  {description}: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            check=True,
            timeout=timeout,
        )
        if capture and result.stdout:
            return result.stdout.strip()
        return None
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else "(keine Fehlerausgabe)"
        raise RuntimeError(f"{description} fehlgeschlagen:\n{stderr}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"{description} ist abgelaufen (Timeout)") from exc

def ensure_hash_files_exist():
    """Check that all expected hash files are present locally."""
    missing = []
    for hf in HASH_FILES:
        path = os.path.join(SCRIPT_DIR, hf)
        if not os.path.isfile(path):
            missing.append(hf)
    if missing:
        print(f"\nFehler: Fehlende Hash-Dateien: {', '.join(missing)}")
        print("  Führen Sie zuerst 'python3 export_hashes.py' aus.")
        sys.exit(1)

def ensure_config_exists(config_file: str):
    """Check that the crack config file exists."""
    path = os.path.join(SCRIPT_DIR, config_file)
    if not os.path.isfile(path):
        print(f"\nFehler: Konfigurationsdatei '{config_file}' nicht gefunden unter {path}")
        sys.exit(1)

# ---------------------------------------------------------------------------
# Main workflow
# ---------------------------------------------------------------------------
def upload_and_crack(
    server: str,
    user: str,
    target_dir: str,
    config_file: str,
    session_name: str,
    devices: str,
    live_results: bool = False,
):
    """Copy hash files to remote server and start cracking."""

    # --- Pre-flight checks ------------------------------------------------
    print("=" * 64)
    print("  Upload & Crack - Vorbereitung")
    print("=" * 64)

    ensure_hash_files_exist()
    ensure_config_exists(config_file)

    ssh_key = check_ssh_key()
    if ssh_key:
        print(f"\n  SSH-Key gefunden: {ssh_key}")
    else:
        print("\n  Hinweis: Kein Standard-SSH-Key gefunden.")
        print("  Stellen Sie sicher, dass die Authentifizierung über")
        print("  ~/.ssh/config oder den standard Schlüssel funktioniert.")

    # --- Build SCP/SSH commands -------------------------------------------
    local_dir = SCRIPT_DIR
    remote_path = f"{user}@{server}:{target_dir}"

    # --- Step 1: Copy hash files via SCP ----------------------------------
    print(f"\n--- Schritt 1: Hash-Dateien nach {remote_path} kopieren ---\n")
    for hf in HASH_FILES:
        src = os.path.join(local_dir, hf)
        dst = f"{remote_path}/{hf}"
        run_command(
            ["scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", src, dst],
            f"SCP {hf}",
        )

    # --- Step 2: Copy config file via SCP ---------------------------------
    print(f"\n--- Schritt 2: Konfiguration kopieren ---\n")
    cfg_src = os.path.join(local_dir, config_file)
    cfg_dst = f"{remote_path}/{config_file}"
    run_command(
        ["scp", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", cfg_src, cfg_dst],
        f"SCP {config_file}",
    )

    # --- Step 3: Start cracking via SSH -----------------------------------
    print(f"\n--- Schritt 3: Cracking-Sitzung starten ---\n")
    crack_cmd = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        f"{user}@{server}",
        f"cd {target_dir} && ./crack.sh -c {config_file} -s {session_name} -d {devices} -o \"-O -w 3\"",
    ]
    if live_results:
        print("  Live-Ergebnisse aktiviert - hashcat-Ausgabe wird im Terminal angezeigt.")
    run_command(
        crack_cmd,
        "Cracking-Sitzung gestartet",
        capture=not live_results,
        timeout=None if live_results else 120,
    )

    # --- Done -------------------------------------------------------------
    print("\n" + "=" * 64)
    print("  Alles erledigt!")
    print(f"  Server : {server}")
    print(f"  Benutzer: {user}")
    print(f"  Zielordner: {target_dir}")
    print(f"  Sitzung : {session_name}")
    print(f"  Geräte  : {devices}")
    print("=" * 64)

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hash-Dateien per SCP/SSH hochladen und Cracking starten.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Beispiel:
  %(prog)s --server hashcat --user kesenheimer \\
           --target /home/kesenheimer/Desktop/cracking/recent \\
           --config crack.conf --session run-01 --devices 5,6,7,8
""",
    )
    parser.add_argument(
        "--server",
        default="hashcat",
        help="IP-Adresse oder Domain des Zielservers (Default: hashcat)",
    )
    parser.add_argument(
        "--user",
        default="kesenheimer",
        help="SSH-Benutzername (Default: kesenheimer)",
    )
    parser.add_argument(
        "--target",
        default="/home/kesenheimer/Desktop/cracking/recent",
        help="Zielverzeichnis auf dem Server (Default: /home/kesenheimer/Desktop/cracking/recent)",
    )
    parser.add_argument(
        "--config",
        default="crack.conf",
        help="Name der crack-Konfigurationsdatei im lokalen Verzeichnis (Default: crack.conf)",
    )
    parser.add_argument(
        "--session",
        default="run-01",
        help="Name der Cracking-Sitzung (Default: run-01)",
    )
    parser.add_argument(
        "--devices",
        default="5,6,7,8",
        help="Kommagetrennte Liste der GPU-Gerätenummern (Default: 5,6,7,8)",
    )
    parser.add_argument(
        "--live-results",
        action="store_true",
        default=False,
        help="Zeige hashcat-Ergebnisse live im Terminal an (deaktiviert Capture).",
    )
    return parser.parse_args()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    args = parse_args()
    upload_and_crack(
        server=args.server,
        user=args.user,
        target_dir=args.target,
        config_file=args.config,
        session_name=args.session,
        devices=args.devices,
        live_results=args.live_results,
    )
