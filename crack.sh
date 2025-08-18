#!/bin/bash

function usage() {
    echo "Usage:"
    echo "$0 [options, ...]"
    echo "-s|--session      session name prefix."
    echo "-r|--restore      restore last session."
    echo "-t|--type         WPA hash type (PMK or PBKDF2 (default))."
    echo "-f|--start-from   start from step x."
    echo "-d|--devices      devices to use (comma separated list)"
    echo "-o|--options      additional options for hashcat"
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
TYPE="PBKDF2"
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
    TYPE="$2"
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
echo "${POSITIONAL[@]}" 


if [[ "$RESTORE" == "true" ]]; then
  if [ ! -f "session.log" ]; then
    echo "Restore file not found. Exiting."
    exit -1
  else
    LAST_SESSION=$(cat session.log)
  fi
fi

HASH_ID=22000
if [[ "$TYPE" == "PMK" ]]; then
  HASH_ID=22001
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
declare -A wordlist rule
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
    fi
done < "$CONFIG_FILE"

for step in "${step_order[@]}"; do
    echo "== Running $step =="
    wordlist_base=""
    rule_base=""

    wordlist="${wordlist[$step]}"
    rule="${rule[$step]}"
    stepi=$(echo "$step" | grep -o '[0-9]\+')

    echo "wordlist = $wordlist"
    echo "rule = $rule"

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
        hashcat -m $HASH_ID -a 0 -o cracked.txt $rule hashes.hc22000 $wordlist --session "$SESSION" -S -d $DEVICES $OPTIONS
        RET_VALUE="$?"
        START_FROM="$((stepi+1))"
    elif [[ "$LAST_SESSION" == "$SESSION" ]]; then
        hashcat --restore --session "$SESSION" $OPTIONS
        RET_VALUE="$?"
        START_FROM="$((stepi+1))"
        RESTORE="false"
    fi
    echo
done

## process and store the results
if [ -f "cracked.txt" ]; then
  cat cracked.txt | cut -d ':' -f4,5 | sort | uniq >> ../cracked-sorted.txt
  cat ../cracked-sorted.txt | sort | uniq > ../cracked-sorted.txt
fi
