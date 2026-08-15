# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo does

WPA/WPA2 handshake capture collection and cracking pipeline. Captured `.pcap` files from Wi‑Fi handshakes (PMKID + EAPOL) are converted to hashcat format and cracked through a configurable multi‑step pipeline of wordlists and rules.

## Directory structure

```
cracking/
├── YYYY-MM-DD-handshakes/   # 48 session dirs (Oct 2023 → Aug 2026)
│   ├── *.pcap               # Raw handshake captures, one per AP
│   ├── hashes.hc22000       # Converted hashcat format (generated)
│   ├── wordlist             # Session-specific wordlist (generated)
│   ├── crack.conf           # Session config copy
│   └── cracked.txt          # Found passwords (generated)
├── all/                     # Catch-all: recent session working directory (135 MB)
├── recent → 2026-08-13-handshakes  # Symlink to latest session
├── *.statistic.txt          # Statistics output from generate-statistics.sh
├── statistics.txt           # Summary of all statistics runs
├── crack.conf               # Main multi-step config (9 steps)
├── crack_weakpass.conf      # Single-step weakpass-only config
├── session.log              # Last active session name (for -r restore)
├── finished.log             # Append-only log of completed sessions
├── crack.sh                 # Main cracking orchestrator
├── prepare.sh               # Session init (hcxpcapngtool, dedup)
├── generate-statistics.sh   # Wordlist hit-rate analysis
├── extract.sh               # Merge all cracked.txt across sessions
├── remove-duplicates.sh     # Remove duplicate pcap files across sessions
├── cross-check (binary)     # C binary: filters candidate passwords against cracked list
├── cross-check.c            # Source for cross-check
├── check (binary)           # C binary: passes stdin through (hex conversion stub)
├── check.c                  # Source for check
└── wpa-benchmark.md         # Hardware cost/rate comparison reference
```

## Common commands

### Crack a new session
```bash
# 1. Prepare (run in the session directory, e.g. all/)
./prepare.sh

# 2. Run cracking with 9-step pipeline from crack.conf
./crack.sh -s 2026-08-13 -d 1,2,3,4 -o "-w 3"
```

### Resume the last active session
```bash
./crack.sh -r
```
Restores the session name stored in `session.log` and continues from where it left off. No `-s` needed.

### Run statistics (wordlist hit-rate analysis)
```bash
./generate-statistics.sh -c ../cracked-sorted.txt -d 1,2,3,4
```
Runs each wordlist from `crack.conf` through hashcat `--stdout`, pipes output through `./cross-check` to count matches against already-cracked passwords. Produces per-wordlist `*.statistic.txt` files and a summary `statistics.txt`.

### Extract cracked passwords from all sessions
```bash
./extract.sh
```
Gathers all `cracked.txt` files across subdirectories into `cracked-sorted.txt`.

### Remove duplicate pcap files across sessions
```bash
./remove-duplicates.sh <directory>
```

### Compile C binaries
```bash
gcc -o cross-check cross-check.c
gcc -o check check.c
```

## Architecture

### Crack pipeline (`crack.sh`)
1. Reads `crack.conf` line-by-line, parsing `[stepN]` sections with `wordlist=` and `rule=` assignments
2. Iterates steps sequentially; each step runs `hashcat -m 22000` (or 22001 for PMK type)
3. Session names are auto-generated as `{prefix}-step{N}-{wordlist_base}{+rule_base}`
4. Supports resuming: if `-r` is given, restores the session in `session.log`; if `-f` is given, skips to that step
5. After each step, checks hashcat exit code: `1`=finished, `2`=manual quit, `3`=checkpoint abort
6. On completion, merges `cracked.txt` into `../cracked-sorted.txt` (deduped globally)

### Preparation (`prepare.sh`)
- Cleans session directory (removes stale session files)
- Runs `hcxpcapngtool -o hashes.hc22000 -E wordlist *.pcap` to extract WPA hashes from all PCAPs
- Deduplicates `wordlist` (sort | uniq)

### Statistics (`generate-statistics.sh`)
- Same config parser as `crack.sh` (reads `crack.conf`)
- Runs `hashcat --stdout` (no cracking, just generates candidates) for each wordlist+rule combo
- Pipes through `./cross-check <cracked-list>` which loads previously cracked passwords into memory and filters matching candidates
- `wc -w *.statistic.txt` counts how many times each wordlist's candidates already appeared in the cracked list — useful for estimating diminishing returns

### Cross-check binary (`cross-check.c`)
- Loads a "cracked passwords" file (parsed for the part after `:`)
- Reads stdin line-by-line (hashcat `--stdout` output)
- Prints only candidates that match an already-cracked password, removing matched entries from memory to avoid duplicate counting

## Config format (`crack.conf`)
```
[step1]
wordlist=/absolute/path/to/wordlist
rule=/absolute/path/to/rule
```

Both `wordlist=` and `rule=` are always present; `rule=` is empty (no rule) when not needed. Steps execute in section-header order (`step1` → `step2` → …). The wordlist value can be an absolute path or a local filename (the session's `wordlist` file created by `prepare.sh`).

## Key conventions
- Hash type 22000 = WPA‑PBKDF2 (PMKID+EAPOL), 22001 = WPA‑PMK
- Session directories are named by capture date: `YYYY-MM-DD-handshakes/`
- `cracked-sorted.txt` lives one level above session dirs (at repo root)
- `hashcat.potfile` is a symlink to `~/.local/share/hashcat/hashcat.potfile`
- `.gitignore` excludes all session data (pcap, hashes, txt output, binaries, symlinks) — only scripts and configs are tracked
