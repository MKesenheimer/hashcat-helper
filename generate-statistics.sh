#!/bin/bash

function usage() {
    echo "Usage:"
    echo "-c|--cracked-list  list of cracked passwords"
    echo "-d|--devices       devices to use (comma separated list)"
    echo "$0 [options, ...]"
    exit 0
}
 
if [ "$#" -lt 2 ]; then
    echo "Illegal number of parameters."
    usage
fi

read -p "Do you want to delete old statistic files? (Y/n): " answer
answer=${answer:-Y}
if [[ "$answer" == "y" || "$answer" == "Y" ]]; then
  rm *.statistic.txt
fi

CONFIG_FILE="crack.conf"
DEVICES=1
CRACKED_LIST=""
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -h|--help)
    usage
    exit 0
    ;;
    -c|--cracked-list)
    CRACKED_LIST="$2"
    shift
    shift
    ;;
    -d|--devices)
    DEVICES="$2"
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

# RET_VALUE:
# 3 -> checkpoint abort
# 2 -> manual quit
# 1 -> finished
RET_VALUE=1

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
    filename="$wordlist_base$rule_base.statistic.txt"
    echo "output filename = $filename"

    #echo "hashcat $rule $wordlist -d $DEVICES --stdout"
    hashcat $rule $wordlist -d $DEVICES --stdout | ./cross-check $CRACKED_LIST | tee -a $filename
    echo
done

# output
wc -w *.statistic.txt | sort -nrk1 | tee statistics.txt
