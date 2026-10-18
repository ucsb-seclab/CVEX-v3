#!/bin/bash
# Stand up vulhub/genie records one by one, logging results, pruning images to save disk.
# Usage: batch_standup.sh <list-file>   (list of record dirs, one per line)
cd /data/vigna/Datasets/CVEX
LOG=tools/lists/standup.tsv
[ -f "$LOG" ] || echo -e "cve\tservice_up\tflag_present\tbenign_ran\tnote" > "$LOG"
while read rec; do
  [ -z "$rec" ] && continue
  cve=$(basename "$rec")
  grep -q "^$cve	" "$LOG" && continue   # already done
  # disk guard: free GB on /
  freeg=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
  if [ "$freeg" -lt 50 ]; then
    docker system prune -af --volumes >/dev/null 2>&1
  fi
  base=$(grep -m1 '^FROM ' "$rec/target/Dockerfile" | awk '{print $2}')
  timeout 2400 python3 tools/cvex_standup.py "$rec" > "/tmp/standup_$cve.log" 2>&1
  if [ -f "$rec/standup.json" ]; then
    su=$(python3 -c "import json;print(json.load(open('$rec/standup.json'))['service_up'])" 2>/dev/null)
    fp=$(python3 -c "import json;print(json.load(open('$rec/standup.json'))['flag_present'])" 2>/dev/null)
    br=$(python3 -c "import json;print(json.load(open('$rec/standup.json'))['benign_ran'])" 2>/dev/null)
    echo -e "$cve\t$su\t$fp\t$br\t" >> "$LOG"
  else
    echo -e "$cve\tERR\t-\t-\t$(tail -1 /tmp/standup_$cve.log | cut -c1-80)" >> "$LOG"
  fi
  # reclaim: remove this record's built images + its base
  docker image rm -f "cvex-${cve,,}-target" "cvex-${cve,,}-benign" "cvex-${cve,,}-recorder" "cvex-${cve,,}-db" >/dev/null 2>&1
  [ -n "$base" ] && docker image rm -f "$base" >/dev/null 2>&1
  rm -rf "$rec/_out" "/tmp/standup_$cve.log"
done < "$1"
echo "BATCH_STANDUP_DONE"
