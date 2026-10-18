#!/bin/sh
# Usage: tools/cvex_batch.sh [cve-list-file]   (default: all unlocked pip-tier records)
# Runs each record; successes self-lock. Prints a SUCCESS/FAILED summary.
d="$PWD"; while [ "$d" != "/" ] && [ ! -d "$d/CVEX-records" ]; do d=$(dirname "$d"); done
cd "$d"
LIST="${1:-}"
if [ -z "$LIST" ]; then
  LIST=/tmp/_cvex_pip.txt; : > "$LIST"
  for d in CVEX-records/CVE-*; do
    [ -f "$d/.cvex-lock" ] && continue
    grep -q 'pip install --no-cache-dir' "$d/target/Dockerfile" 2>/dev/null && basename "$d" >> "$LIST"
  done
fi
ok=0; fail=0
while read cve; do
  [ -z "$cve" ] && continue
  python3 tools/cvex_run.py "CVEX-records/$cve" --settle 2 >/tmp/run_$cve.log 2>&1
  v="CVEX-records/$cve/dataset/verdict.json"
  if [ -f "$v" ] && python3 -c "import json,sys;sys.exit(0 if json.load(open('$v'))['success'] else 1)" 2>/dev/null; then
    echo "SUCCESS $cve"; ok=$((ok+1))
  else
    echo "FAILED  $cve"; rm -rf "CVEX-records/$cve/dataset"; fail=$((fail+1))
  fi
  docker ps -aq --filter name=cvex-cve- | xargs -r docker rm -f >/dev/null 2>&1
  docker network ls --filter name=cvexnet -q | xargs -r docker network rm >/dev/null 2>&1
done < "$LIST"
echo "BATCH_DONE ok=$ok fail=$fail"
