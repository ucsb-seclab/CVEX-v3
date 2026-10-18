# CVEX v3 tooling

Recovered/rebuilt CVEX v3 tools. They assume this layout (siblings on disk):

```
CVEX/
  tools/            # these scripts (run them from here; ROOT is the parent dir)
  CVEX-records/     # the records (clone of ucsb-seclab/CVEX-v3-records)
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

`migrate_to_v3.py` (gen-3 Vagrant -> v3) was lost in the Oct 2026 incident and is
being rebuilt.
