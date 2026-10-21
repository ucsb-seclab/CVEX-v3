#!/bin/bash
# Verify records with cvex_run (the Genie verifier / flag decides success).
# Locks + commits + pushes the ones that pass. Usage: batch_verify.sh <list-file>
cd /data/vigna/Datasets/CVEX
LOG=tools/lists/verify.tsv; REPO=CVEX-records
[ -f "$LOG" ] || printf "cve\tresult\tnote\n" > "$LOG"
push(){ git -C "$REPO" commit -q -m "$1" 2>/dev/null || return 0
  for t in 1 2 3; do git -C "$REPO" push -q origin main 2>/dev/null && return 0
    git -C "$REPO" pull -q --no-edit --no-rebase origin main 2>/dev/null; sleep 3; done; }
while read rec; do
  [ -z "$rec" ] && continue
  cve=$(basename "$rec")
  grep -q "^$cve	" "$LOG" && continue
  [ -f "$rec/.cvex-lock" ] && { printf "%s\talready-locked\t\n" "$cve" >> "$LOG"; continue; }
  freeg=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
  [ "$freeg" -lt 60 ] && { docker image prune -af >/dev/null 2>&1; docker builder prune -af >/dev/null 2>&1; }
  rm -f "$rec/.cvex-lock"; rm -rf "$rec/dataset"
  timeout 1800 python3 tools/cvex_run.py "$rec" --settle 2 --pin > "/tmp/verify_$cve.log" 2>&1
  if [ -f "$rec/dataset/verdict.json" ] && python3 -c "import json,sys;sys.exit(0 if json.load(open('$rec/dataset/verdict.json'))['success'] else 1)" 2>/dev/null; then
    printf "%s\tVERIFIED\t\n" "$cve" >> "$LOG"
    git -C "$REPO" add "$cve" >/dev/null 2>&1
    cp "$LOG" "$REPO/VERIFY_RESULTS.tsv"; git -C "$REPO" add VERIFY_RESULTS.tsv 2>/dev/null
    push "verify $cve (PASS)"
  else
    note=$(tail -1 "/tmp/verify_$cve.log" 2>/dev/null | tr -d '\t' | cut -c1-80)
    printf "%s\tfailed\t%s\n" "$cve" "$note" >> "$LOG"
    git -C "$REPO" checkout -- "$cve" 2>/dev/null; git -C "$REPO" clean -fdq "$cve" 2>/dev/null
  fi
  docker image rm -f "cvex-${cve,,}-target" "cvex-${cve,,}-recorder" >/dev/null 2>&1
  base=$(grep -m1 '^FROM ' "$rec/target/Dockerfile" 2>/dev/null | awk '{print $2}')
  rm -rf "$rec/_out" "/tmp/verify_$cve.log"
done < "$1"
echo "BATCH_VERIFY_DONE"
