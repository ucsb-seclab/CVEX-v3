# CVEX v3 tooling

Recovered/rebuilt CVEX v3 tools. They live in this repo (`CVEX-v3/tools/`) and
locate the records by searching upward from the current directory for a
`CVEX-records/` folder, so run them from a working tree laid out as:

```
work/
  CVEX-v3/        # this repo (contains tools/)
  CVEX-records/   # clone of ucsb-seclab/CVEX-v3-records
  Historic/       # the historical CVEX repos (migration source), optional
  tools -> CVEX-v3/tools   # convenience symlink, so `python3 tools/...` works
```

Key scripts:
- `cvex_run.py <record> [--settle N] [--pin]` — build a record offline, run the
  benign and attack phases, capture pcap + syscalls, verify the flag/crash, and
  write `dataset/` + `verdict.json`. `--pin` writes the built image ids into the
  record's `cvex.yml` `@sha256` pins (a new reference build).
- `cvex_check.py [--status] <records...>` — conformance checker (digest pins,
  offline build, vendored+checksummed inputs, real benign workload, dataset).
- `cvex_vendor_debs.sh <base@sha256> <outdir> <pkg>...` — vendor .debs for an
  offline build, writing `SHA256SUMS` and `debs.lock`.
- `gen_todo.py`, `genie_stackharness.py`, `genie_replay.py`, `cvex_batch.sh`,
  `cvex_quarantine.sh` — batch migration/triage helpers.
- `conform10.py` — one-off generator for the 10 fully-conformant gold records.

`migrate_to_v3.py [CVE...]` scaffolds gen-3 (Vagrant/Ansible) records from
`Historic/CVEX-records/` into v3 format (rewritten after the Oct 2026 incident).
