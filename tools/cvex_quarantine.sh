#!/bin/sh
# Usage: cvex_quarantine.sh <CVE> "<reason>" [evidence-log]
d="$PWD"; while [ "$d" != "/" ] && [ ! -d "$d/CVEX-records" ]; do d=$(dirname "$d"); done
cd "$d"
cve="$1"; reason="$2"; log="$3"
src="CVEX-records/$cve"; dst="CVEX_v3-unreproduced/$cve"
[ -d "$src" ] || { echo "no such record $cve"; exit 1; }
mkdir -p CVEX_v3-unreproduced
rm -rf "$dst"; mv "$src" "$dst"
repo=$(python3 -c "import json;print(json.load(open('$dst/_source/cve_info.json')).get('sw_version_wget',''))" 2>/dev/null)
ver=$(python3 -c "import json;print(json.load(open('$dst/_source/cve_info.json')).get('sw_version',''))" 2>/dev/null)
status=$(curl -s -o /dev/null -w '%{http_code}' -L "$repo" 2>/dev/null)
{
  echo "# $cve — could not be reproduced automatically"
  echo
  echo "- Vulnerable software: $(echo "$repo"|sed 's#/archive.*##;s#https://github.com/##') @ $ver"
  echo "- Source URL: $repo  (HTTP $status$([ "$status" = 404 ] && echo ' — UPSTREAM SOURCE GONE'))"
  echo "- Reason: $reason"
  echo
  echo "## What's here"
  echo "- \`target/\`, \`cvex.yml\` — the v3 scaffold / harness attempted"
  echo "- \`_source/exploit.py\`, \`_source/verifier.py\` — CVE-Genie's real exploit + verifier (the oracle)"
  echo "- \`_source/cve_info.json\` — metadata (CWE, patch commits, description, source URL+version)"
  echo "- Full CVE-Genie agent logs: \`cve-genie/results/reproduced_cves/$cve/conversations/\`"
  echo
  echo "## For a human to finish"
  echo "1. Obtain the exact vulnerable source ($ver). If the URL 404s, find the commit via the"
  echo "   patch-commit parent in cve_info.json, or a fork/mirror."
  echo "2. Stand up the environment the verifier assumes (see conversations/repo_builder.json 'access')."
  echo "3. Run: \`python3 tools/cvex_run.py CVEX_v3-unreproduced/$cve\` (move back to CVEX-records/ once green)."
  [ -n "$log" ] && [ -f "$log" ] && { echo; echo "## Last failure output"; echo '```'; tail -20 "$log"; echo '```'; }
} > "$dst/README.md"
echo "quarantined $cve ($status) -> $dst"