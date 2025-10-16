#!/bin/bash

directory=$1
pcap_files=$(ls $1/*.pcap)

for f in $pcap_files; do
  [[ -f "$f" ]] || continue
  file=$(basename "${f%%_*}")
  echo "Checking $file"
  count=$(find . -iname "$file*" | wc -l)
  echo "-> $count"
  if [ $count -gt 1 ]; then
    echo "-> Removing $f"
    rm $f
  fi
done
