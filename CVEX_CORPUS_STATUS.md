# CVEX Corpus Status

This note tracks the CVEX v3 record corpus. The format itself is defined in
[`CVEX_v3_DESIGN.md`](CVEX_v3_DESIGN.md); the full list of CVE ids (active +
quarantined) is in [`EXISTING_RECORDS.txt`](EXISTING_RECORDS.txt). Records live
in the `ucsb-seclab/CVEX-v3-records` repo; the tooling is in
[`tools/`](tools/README.md).

_Last updated: 2026-10-19._

---

## 1. Totals

| | count |
|---|---|
| **Total records** | **691** |
| Active | 656 |
| Quarantined (`CVEX-records/quarantine/`) | 35 |

By origin:

| Source | Records | Notes |
|---|---|---|
| **cve-genie** | 429 | CVE-Genie reproductions (394 active + 35 quarantined) |
| **vulhub** | 238 | vulhub environments |
| **curated** | 24 | hand-built from the historical CVEX corpus (gen-3 Vagrant) |

---

## 2. Conformance tiers

A record is **conformant** when it installs the vulnerable service, ships a
benign interaction and a planted flag, and builds offline (`--network=none`,
digest-pinned or vendored base). Success is a captured flag, a crash witness, or
the included CVE-Genie verifier. **No exploit is authored for the vulhub/cve-genie
corpus** — an exploit is included only where one already ships (34 vulhub PoCs,
all 429 Genie verifiers). Records are verified with `tools/cvex_check.py` (full
conformance, flag captured) or `tools/cvex_standup.py` (service stands up + flag
planted + benign runs, no attacker needed).

### curated (24)

- **10 fully conformant & verified** (gold): offline, digest-pinned, with a
  committed benign/attack reference dataset and a working included exploit — they
  pass `tools/cvex_check.py`. Three of them (CVE-2017-12617, CVE-2021-41773,
  CVE-2015-1427) additionally **vendor their base image** (`base-images/`) so they
  reproduce with zero network even if the upstream image disappears.
- **14 scaffolds**: full v3 structure + preserved gen-3 source in `_source/`;
  exploit, vulnerable build, and benign workload are TODO.

### vulhub (238)

- **183 stand-up-ready**: the vulnerable service builds and runs, the flag is
  planted, and the benign interaction runs (`standup.json`). 34 of these include
  the exploit vulhub ships.
- **55 not yet standing up**: per-record issues (a mis-guessed port, a required
  custom start command, or a DB-backed app needing schema/migration setup). Each
  is flagged in its `TODO.md` and in `STANDUP_RESULTS.tsv`.

### cve-genie (429)

- **394 stand-up-ready**: the target builds the vulnerable software from the
  source archive, the flag is planted, and benign use runs. All include the
  CVE-Genie `exploit.py` + `verifier.py`.
- **35 quarantined** — see below.

---

## 3. Quarantine (35)

All 35 are `lunary-ai/lunary` CVE-Genie records. Their pinned source archives
(`github.com/lunary-ai/lunary/archive/refs/tags/v<X>.zip`) now return HTTP 404 —
the upstream tags/release archives were removed — so the vulnerable service cannot
be built. They are kept under `CVEX-records/quarantine/` with their `_source/` so
they can be revived if the source reappears (a fork, a cached archive, or a clone
pinned to the vulnerable commit). See `CVEX-records/quarantine/README.md`.

This is the same failure mode that threatens any record depending on an external
registry or archive: pinning by digest guarantees *integrity* (you get the exact
tested bytes, or a hard failure), not *availability*. The committed dataset
survives regardless; vendoring the base image (as the 3 flagship records do)
closes the remaining gap so the environment survives too.

---

## 4. Summary

- **691 records** in the format; **656 active**, **35 quarantined**.
- **577 active records stand up** (service + flag + benign): 183 vulhub + 394
  cve-genie, plus the 10 verified curated gold records and 24 curated total.
- Reproducibility rests on the committed datasets and, for the flagship records,
  vendored base images; the rest reference digest-pinned upstream images and so
  depend on those remaining hosted.
