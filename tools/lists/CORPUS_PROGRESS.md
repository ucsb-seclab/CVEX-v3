# Corpus build progress (vulhub + cve-genie -> CVEX v3)

Goal: make vulhub and cve-genie CVEs CVEX-v3 conformant. Install the vulnerable
service, add a BENIGN interaction and flag placement; include an exploit only if
one already ships (none authored here).

Tools: tools/vulhub_to_v3.py, tools/genie_to_v3.py, tools/cvex_standup.py,
tools/batch_standup.sh. Results: tools/lists/standup.tsv.

- Records scaffolded: 240 vulhub + 429 cve-genie.
- Stand-up = service builds + runs, flag planted, benign runs (no exploit needed).
- Run: `bash tools/batch_standup.sh tools/lists/<vulhub|genie>_records.txt`
