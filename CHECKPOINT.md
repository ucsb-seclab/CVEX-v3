# CVEX v3 — session checkpoint (2026-10-21)

Hand-off for a fresh session. Working dir: `/data/vigna/Datasets/CVEX`.
**Everything important is pushed to GitHub** (see repos below) — the working dir
itself is NOT a git repo and was once wiped, so trust the repos, not local-only files.

---

## 1. Layout

```
/data/vigna/Datasets/CVEX/
  tools/            -> symlink to CVEX-v3/tools (the canonical tooling)
  CVEX-records/     git repo  ->  ucsb-seclab/CVEX-v3-records   (the records; LFS for big blobs)
  CVEX-v3/          git repo  ->  ucsb-seclab/CVEX-v3           (format docs, tools/, techreport/)
  Historic/         fresh clones of the historical repos (migration SOURCES, read-only):
                      Historic/vulhub/<product>/CVE-*/          (vulhub environments)
                      Historic/cve-genie/results/reproduced_cves/CVE-*/  (CVE-Genie repros)
                      Historic/CVEX-records/CVE-*/              (gen-3 Vagrant curated originals)
  .vend/            reconstructed vendored packages (gitignored): build, apache2, client,
                    recorder, node, py, npm, strace-deb, requirements.lock
```
Both repos are **in sync with origin** as of this checkpoint.

Git: tools in `CVEX-v3/tools/` resolve the records dir by searching upward from CWD
for `CVEX-records/`, so run tool commands from `/data/vigna/Datasets/CVEX`.

---

## 2. Corpus status (692 records)

| | count |
|---|---|
| Total | 692 (657 active + 35 quarantined) |
| **Verified & locked** (`.cvex-lock`, exploit/verifier captured, has dataset) | **106** |
| Quarantined (`CVEX-records/quarantine/`, lunary upstream-gone 404) | 35 |

By source: cve-genie 394 active (90 locked), vulhub 238 (4 locked), curated 24 (11 locked),
manual 1 (XWiki, locked).

"Locked" = `tools/cvex_run.py` built it, ran benign+attack, and the flag/verifier/crash
succeeded. A subset are also fully `cvex_check`-conformant (offline, digest-pinned,
vendored, paired dataset): the 10 gold + XWiki + Shellshock; 3 of those (CVE-2017-12617,
CVE-2021-41773, CVE-2015-1427) additionally vendor their base image.

---

## 3. Tools (in `CVEX-v3/tools/`, run from the working dir)

- `cvex_run.py <record> [--settle N] [--pin]` — build offline, run benign+attack, capture
  pcap+syscalls, verify (flag/verifier/crash), write `dataset/`, self-lock on success.
  `--pin` writes built image ids into `cvex.yml`. Starts db before target for `target+db`.
- `cvex_check.py [--status] <records>` — conformance (digest pins, offline build, vendored
  checksums, real benign, flag-in-pcap, dataset). PASS = fully conformant.
- `cvex_standup.py <record>` — the no-exploit check: builds target(+db), confirms the
  service stands up + flag planted + benign runs. Per-record docker network.
- `cvex_vendor_debs.sh <img@sha256> <outdir> <pkg>...` — vendor .debs offline.
- `vulhub_to_v3.py` / `genie_to_v3.py` / `migrate_to_v3.py` — scaffolders (vulhub / cve-genie /
  gen-3 curated). `conform10.py` — one-off for the 10 gold records.
- `batch_standup.sh <list>` — stand up a list, push each as ready.
- `batch_verify.sh <list>` — cvex_run a list, lock+push passes, revert failures.
- `migrate_to_v3.py` lost in the Oct-2026 incident was rewritten; `genie_to_v3.py` installs
  pip+requests in targets.

---

## 4. What's done vs. what's left (completeness tiers)

- **Verified (106).** Done.
- **cve-genie — tier A, DONE to its ceiling.** 90/394 verified; **304 need per-record work**,
  triaged in `CVEX-records/GENIE_TRIAGE.tsv` (classes: needs-service-started / needs-real-build /
  needs-external-tool / missing-module). These are single-host (verifier runs locally) so they
  generate no attacker↔target network traffic. Ceiling is structural: our scaffold installs the
  software but doesn't *start the service* or *do a real build* before the verifier.
- **vulhub PoCs — tier B, mostly exhausted.** Of 34 shipped PoCs only ~9 fit the flag model;
  ~20 are blind RCE (would need exfiltration = new exploit, DISALLOWED), 5 don't fit. Verified:
  CVE-2017-11610 (Supervisor), CVE-2025-41242 (Spring Boot LFI).
- **vulhub "won't stand up" — tier C, 50** records build but never reach ready (wrong port /
  needs start command / DB migration). Not yet triaged in depth.
- **curated scaffolds — tier E, 13 left.** Each has full `_source/` (gen-3 playbooks + data +
  usually the exploit). **Worked example done: CVE-2014-6271 Shellshock** (full conformant).
  Guide + assignment table: `CVEX-v3/AUTHORING.md`.
- **"Easy" medium-tier wins via known public techniques** (service stands up + a simple
  output-returning public exploit I include, not develop). Recently verified this way:
  CVE-2017-12615 (Tomcat PUT-JSP, reused the gold CVE-2017-12617 exploit), CVE-2017-9841 (phpUnit).
  CVE-2012-1823 (php-cgi) attempted and reverted (URL-encoding needs tuning).

### Worklists (in the repo, ready to use)
- `CVEX-records/OPEN_NETWORK_TODO.tsv` — 230 not-done, open-source, network-accessed records.
- `CVEX-records/OPEN_NETWORK_RANKED.tsv` — those 230 ranked by ease (but note: ranking over-weights
  "ships a PoC"; many PoCs are blind — see below).
- `CVEX-records/GENIE_TRIAGE.tsv` — the 304 unverified genie, by what each needs.
- `CVEX-records/{STANDUP,VERIFY}_RESULTS.tsv` — stand-up / verification outcomes.
- `tools/lists/*` — the raw worklists the batches consume.

---

## 5. How to continue (recommended next moves)

1. **Medium-tier public-technique wins** (most productive, honors "no new exploit"): for a
   vulhub record that stands up and whose CVE has a simple, documented, OUTPUT-RETURNING
   exploit (RCE that echoes output, or file-read), write `attacker/exploit.sh` to run that
   public technique reading `/flag`, then `python3 tools/cvex_run.py CVEX-records/<CVE> --pin`.
   Good candidates: CVE-2022-22947 (Spring Cloud Gateway), CVE-2024-23897 (Jenkins arg file-read),
   CouchDB, Laravel Ignition. **Skip blind RCE** (no output) — capturing /flag there needs
   exfiltration, which is exploit development and is OUT OF SCOPE per the user.
2. **Tier E** — author the 13 curated scaffolds following `CVEX-v3/AUTHORING.md`; Shellshock
   (`CVEX-records/CVE-2014-6271`) is the reference. Easiest next: CVE-2019-18276 (bash privesc,
   like the sudo gold records), CVE-2020-1938 (Ghostcat file-read, like the httpd records).
3. **Tier C** — triage the 50 vulhub "won't stand up": check the real container port / needed
   start command / db migration; re-`cvex_standup.py`.
4. **cve-genie per-record** — hard; use `GENIE_TRIAGE.tsv`; each failing record's run-instructions
   are in `_source/conversations/repo_builder.json` (`access`).

Constraint from the user, throughout: **do NOT develop new exploits.** Include a shipped or
public one, adapted only to read `/flag`. For records with no usable public exploit, the
deliverable is service + benign + flag (stand-up), not a verified attack.

---

## 6. Gotchas / lessons (all encountered and solved)

- **Shell aliases** `cp`/`mv`/`rm` are interactive; use `/bin/cp -f` etc. **Never `pkill -f <name>`**
  (kills the shell, exit 144); use `TaskStop` for background tasks.
- **A failed `cvex_run` deletes the record's dataset and unlocks it** — back up a locked record
  before re-running, or just regenerate.
- **Apache in a minimal image:** create `/var/run/apache2/socks` (else mod_cgid 503), source
  `/etc/apache2/envvars`, run foreground.
- **`flag travels in the attack pcap` fails though the exploit works:** the request finished
  before capture went live → have `exploit.sh` re-send the flag request a few times after success.
- **HTML-escaped flag:** some apps escape `{` as `&#123;` → parse `CVEX(\{|&#123;)[0-9a-f]{32}`
  and reconstruct; use `stdout` channel when the literal flag can't cross the wire verbatim.
- **DB-backed apps (XWiki):** interactive/network first-boot can't be fully automated — complete
  setup once by hand, then bake the state (db dump auto-imported + permanent dir baked into the
  image). `cvex_run` now starts db first + passes db alias/env; set `db_warmup_seconds` in cvex.yml.
- **Big JVM syscall logs:** `cvex_run` gzips traces >20 MB automatically.
- **Disk is the main constraint (92% used, ~312 GB free).** Batches prune images between records;
  when pulling heavy images (gitlab ~2 GB, etc.) watch `df -h /`. Don't `docker system prune`
  without care — unrelated containers/images exist on this host.

---

## 7. Recently finished this session
- Rebuilt the whole project after the Oct-2026 data-loss incident; recovered tools + the paper.
- Authored CVE-2025-24893 (XWiki, new record) — see its `REPORT.md`.
- Shellshock worked example + `AUTHORING.md`.
- cve-genie verification batch (tier A), vulhub PoC wiring (tier B), the ranked worklists.
- Docs: `CVEX-v3/{CVEX_v3_DESIGN.md, CVEX_CORPUS_STATUS.md, EXISTING_RECORDS.txt, REFERENCE_RECORDS.md, AUTHORING.md}`.
