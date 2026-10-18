#!/bin/bash
# Stand up vulhub/genie records one by one; commit+push each as it becomes ready;
# prune images between records to save disk.
# Usage: batch_standup.sh <list-file>   (list of record dirs, one per line)
cd /data/vigna/Datasets/CVEX
LOG=tools/lists/standup.tsv
REPO=CVEX-records
[ -f "$LOG" ] || printf "cve\tservice_up\tflag_present\tbenign_ran\tnote\n" > "$LOG"

push() {  # commit staged changes and push; never fatal
  git -C "$REPO" commit -q -m "$1" 2>/dev/null || return 0
  for try in 1 2 3; do
    git -C "$REPO" push -q origin main 2>/dev/null && return 0
    git -C "$REPO" pull -q --no-edit --no-rebase origin main 2>/dev/null
    sleep 3
  done
}

n=0
while read rec; do
  [ -z "$rec" ] && continue
  cve=$(basename "$rec")
  grep -q "^$cve	" "$LOG" && continue   # already processed
  freeg=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
  if [ "$freeg" -lt 50 ]; then
    docker image prune -af >/dev/null 2>&1; docker builder prune -af >/dev/null 2>&1
  fi
  base=$(grep -m1 '^FROM ' "$rec/target/Dockerfile" 2>/dev/null | awk '{print $2}')
  timeout 2400 python3 tools/cvex_standup.py "$rec" > "/tmp/standup_$cve.log" 2>&1
  if [ -f "$rec/standup.json" ]; then
    su=$(python3 -c "import json;print(json.load(open('$rec/standup.json'))['service_up'])" 2>/dev/null)
    fp=$(python3 -c "import json;print(json.load(open('$rec/standup.json'))['flag_present'])" 2>/dev/null)
    br=$(python3 -c "import json;print(json.load(open('$rec/standup.json'))['benign_ran'])" 2>/dev/null)
    printf "%s\t%s\t%s\t%s\t\n" "$cve" "$su" "$fp" "$br" >> "$LOG"
    ready="no"; [ "$su" = "True" ] && [ "$fp" = "True" ] && ready="yes"
  else
    printf "%s\tERR\t-\t-\t%s\n" "$cve" "$(tail -1 /tmp/standup_$cve.log 2>/dev/null | cut -c1-80)" >> "$LOG"
    ready="no"
  fi
  # reclaim disk: drop this record's built images + its base
  docker image rm -f "cvex-${cve,,}-target" "cvex-${cve,,}-benign" "cvex-${cve,,}-recorder" "cvex-${cve,,}-db" >/dev/null 2>&1
  [ -n "$base" ] && docker image rm -f "$base" >/dev/null 2>&1
  rm -rf "$rec/_out" "/tmp/standup_$cve.log"
  # commit+push this record's result (and the standup log) as it becomes ready
  git -C "$REPO" add "$(basename "$rec")" >/dev/null 2>&1
  cp "$LOG" "$REPO/STANDUP_RESULTS.tsv"; git -C "$REPO" add STANDUP_RESULTS.tsv 2>/dev/null
  push "standup $cve (ready=$ready)"
  n=$((n+1))
done < "$1"
echo "BATCH_STANDUP_DONE processed=$n"
