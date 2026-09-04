#!/bin/bash

function usage() {
    echo "Usage:"
    echo "$0 [options, ...]"
    echo "-s|--session      session name prefix."
    echo "-r|--restore      restore last session."
    echo "-t|--type         hash type (default 22000)."
    echo "-c|--config       config file to use (default crack.conf)."
    echo "-f|--start-from   start from step x."
    echo "-d|--devices      devices to use (comma separated list)"
    echo "-o|--options      additional options for hashcat"
    echo
    echo "Examples:"
    echo "  ./crack.sh -s 2026-06-11 -d 5,6,7,8 -o \"-w 3\""
    echo "  ./crack.sh -s 2026-06-11 -r"
    echo
    echo "Monitoring:"
    echo "  Monitor status via web UI: python3 status-server.py"
    echo "  Or CLI: ./poll-status.sh"
    exit 0
}
 
if [ "$#" -lt 1 ]; then
    echo "Illegal number of parameters."
    usage
fi

OPTIONS=""
CONFIG_FILE="crack.conf"
START_FROM="1"
RESTORE="false"
DEVICES=1
HASH_ID="22000"
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -h|--help)
    usage
    exit 0
    ;;
    -s|--session)
    SESSION_PRE="$2"
    shift
    shift
    ;;
    -r|--restore)
    RESTORE="true"
    shift
    ;;
    -t|--type)
    HASH_ID="$2"
    shift
    shift
    ;;
    -c|--config)
    CONFIG_FILE="$2"
    shift
    shift
    ;;
    -f|--start-from)
    START_FROM="$2"
    shift
    shift
    ;;
    -d|--devices)
    DEVICES="$2"
    shift
    shift
    ;;
    -o|--options)
    OPTIONS="$2"
    shift
    shift
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
  esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters
#echo "${POSITIONAL[@]}" 


if [[ "$RESTORE" == "true" ]]; then
  if [ ! -f "session.log" ]; then
    echo "Restore file not found. Exiting."
    exit -1
  else
    LAST_SESSION=$(cat session.log)
    echo "Restoring last session $LAST_SESSION"
  fi
fi

# RET_VALUE:
# 3 -> checkpoint abort
# 2 -> manual quit
# 1 -> finished
RET_VALUE=1

# check already found passwords
cat ~/.local/share/hashcat/hashcat.potfile | cut -d ':' -f2 | sort | uniq > ~/wordlists/potfile-cracked.txt

# Read config line by line
current_step=""
declare -A wordlist rule type hashfile
step_order=()

while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"    # Remove comments
    line="${line%"${line##*[![:space:]]}"}" # Trim trailing space
    line="${line#"${line%%[![:space:]]*}"}" # Trim leading space

    [ -z "$line" ] && continue

    if [[ "$line" =~ \[(.*)\] ]]; then
        current_step="${BASH_REMATCH[1]}"
        step_order+=("$current_step")
    elif [[ "$line" =~ ^wordlist=(.*) ]]; then
        wordlist["$current_step"]="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^rule=(.*) ]]; then
        rule["$current_step"]="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^type=(.*) ]]; then
        type["$current_step"]="${BASH_REMATCH[1]}"
    elif [[ "$line" =~ ^file=(.*) ]]; then
        hashfile["$current_step"]="${BASH_REMATCH[1]}"
    fi
done < "$CONFIG_FILE"

WPA_RESULTS="false"
for step in "${step_order[@]}"; do
    echo "== Running $step =="
    wordlist_base=""
    rule_base=""

    wordlist="${wordlist[$step]}"
    rule="${rule[$step]}"
    step_type="${type[$step]}"
    step_hashfile="${hashfile[$step]}"
    stepi=$(echo "$step" | grep -o '[0-9]\+')

    # fall back to defaults when not given in the config
    [ -z "$step_type" ] && step_type="$HASH_ID"
    [ -z "$step_hashfile" ] && step_hashfile="hashes.hc22000"

    # only WPA results go into cracked-sorted.txt
    if [[ "$step_type" == "22000" || "$step_type" == "22001" ]]; then
        WPA_RESULTS="true"
    fi

    echo "wordlist = $wordlist"
    echo "rule = $rule"
    echo "type = $step_type"
    echo "file = $step_hashfile"

    if [ -n "$wordlist" ]; then
        wordlist_base="$(basename ${wordlist})"
    fi
    if [ -n "$rule" ]; then
        rule_base="+$(basename ${rule})"
        rule="-r $rule"
    fi
    #echo $wordlist_base $rule_base

    SESSION="$SESSION_PRE-step$stepi-$wordlist_base$rule_base"
    if [[ "$RESTORE" == "false" ]] && [[ "$START_FROM" == "$stepi" ]]; then
        echo "$SESSION" > session.log
        echo "hashcat -m $step_type -a 0 -o cracked.txt $rule $step_hashfile $wordlist --session \"$SESSION\" -S -d $DEVICES --status --status-timer 1 $OPTIONS"
        hashcat -m $step_type -a 0 -o cracked.txt $rule $step_hashfile $wordlist --session "$SESSION" -S -d $DEVICES --status --status-timer 1 $OPTIONS
        RET_VALUE="$?"
        START_FROM="$((stepi+1))"
    elif [[ "$LAST_SESSION" == "$SESSION" ]]; then
        hashcat --restore --session "$SESSION" --status --status-timer 1 $OPTIONS
        RET_VALUE="$?"
        START_FROM="$((stepi+1))"
        RESTORE="false"
    fi
    echo "$SESSION" >> finished.log    

    # check return value
    if [[ "$RET_VALUE" == "3" ]]; then
        echo "Checkoint abort"
        break
    fi

    echo
done

## process and store the results
if [ -f "cracked.txt" ] && [[ "$WPA_RESULTS" == "true" ]]; then
  cat cracked.txt | cut -d ':' -f4,5 | sort | uniq >> ../cracked-sorted.txt
  sort -u -o ../cracked-sorted.txt ../cracked-sorted.txt
fi
