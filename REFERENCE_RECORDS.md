# Reference records

Three records in the corpus are designated **reference records**. They are the
highest-assurance examples of the CVEX v3 format and are meant to be the ones you
point people at, cite in the paper, and test tooling against. They live in
`ucsb-seclab/CVEX-v3-records`.

| CVE | Software | Vulnerability | Topology | Flag channel | `cvex_check` |
|---|---|---|---|---|---|
| **CVE-2017-12617** | Apache Tomcat 9.0.0.M1 | JSP upload via `PUT` (trailing-slash) → RCE | target → attacker | network | PASS (59/59) |
| **CVE-2021-41773** | Apache httpd 2.4.49 | Encoded path traversal → file disclosure | target → attacker | network | PASS (57/57) |
| **CVE-2015-1427** | Elasticsearch 1.4.2 | Groovy sandbox bypass → RCE | target → attacker | network | PASS (57/57) |

---

## Why they are different from the rest of the corpus

Most of the ~690 records are either (a) curated scaffolds, or (b) vulhub /
cve-genie records that have been *stood up* (service builds, flag planted, benign
runs) but whose exploit is only present if one already shipped. The three
reference records clear a strictly higher bar on **every** axis at once:

### 1. A real, included, working exploit — verified end to end
Each ships an exploit that actually runs against the live service and **captures
the planted flag**, and the runner confirms `flag_planted == flag_observed`. This
is `success: flag` (not a crash witness, not a deferred verifier, not a TODO).
Most corpus records are verified only by *stand-up* (`cvex_standup.py`: service +
flag + benign, no attacker); these three are verified by full exploitation
(`cvex_run.py`).

### 2. The flag crosses the network and is captured in the dataset
All three are `target → attacker` over the network, and the committed
`dataset/attack/attack.pcap` **contains the flag bytes** — proof the exploit
genuinely drove the vulnerability over the wire, not a side channel. Each record
ships a paired, committed reference dataset:
`dataset/{benign,attack}/{*.pcap,*.syscalls.log}`, plus `verdict.json`,
`flag.observed`, and a `MANIFEST.sha256`. The benign and attack phases are run
from a pristine target, so the two captures are directly comparable — a labeled
benign-vs-attack dataset.

### 3. Fully offline **and** registry-independent (vendored base images)
Every record in the corpus builds offline (`--network=none`) against a
digest-pinned base, but a digest only guarantees *integrity*, not *availability* —
if Docker Hub drops the image, the environment is gone (this is exactly what
happened to the 35 quarantined `lunary` records when their source archives 404'd).

The three reference records remove that dependency: the pinned base image is
`docker save`d into the record under `base-images/target.image.tar` (with a
`SHA256SUMS` and a `MANIFEST.txt` recording the original `ref@digest`), and the
target `Dockerfile`'s `FROM` points at a local tag that `cvex_run` loads from that
tar before building. They were each verified by **purging the base image from the
Docker cache entirely** and rebuilding from the vendored bytes alone:

```
# with httpd:2.4.49 / eclipse-temurin / vulhub-elasticsearch absent from the cache:
python3 tools/cvex_run.py CVEX-records/CVE-2021-41773 --pin   # loads base, builds offline, SUCCESS
```

So these records reproduce with **zero network access, forever** — even if the
upstream images disappear from the registry. No other records vendor their base
image (doing it for all ~690 would be multiple TB of git-LFS).

### 4. Open-source, actively-developed software
All three target projects are open source and still actively developed (Apache
Tomcat and Apache httpd under the ASF; Elasticsearch, actively developed and AGPL
again since late 2024). The vulnerable *versions* are old, but the software is
live — so the records stay relevant as teaching/benchmark examples.

---

## Per-record detail

### CVE-2017-12617 — Apache Tomcat JSP-upload RCE
- Base: `eclipse-temurin:8-jdk-jammy` (vendored, 267 MB) + a vendored Tomcat
  9.0.0.M1 tarball — the **only** reference record whose application layer is also
  a vendored file, not just a base image.
- Target ready on `tcp:8080`, traced process `java`, flag at `/flag`.
- Exploit: `PUT` a JSP (trailing-slash bypass) that reads `/flag`, then GET it;
  the JSP is re-fetched a few times so the flag reliably lands in the capture.

### CVE-2021-41773 — Apache httpd 2.4.49 path traversal
- Base: `httpd:2.4.49` (vendored, 136 MB).
- Target ready on `tcp:80`, traced process `httpd`, flag at `/opt/secret/flag`
  (outside the web root — a legitimate request can never reach it).
- Exploit: encoded `..%2e` traversal that reads the secret file.

### CVE-2015-1427 — Elasticsearch 1.4.2 Groovy RCE
- Base: `vulhub/elasticsearch:1.4.2` (vendored, 469 MB).
- Target ready on `tcp:9200`, traced process `java`, flag at `/flag`.
- Exploit: a Groovy `script_fields` sandbox bypass that executes `cat /flag`.

---

## Using them

```
# full exploitation + verification (rebuilds offline from the vendored base):
python3 tools/cvex_run.py CVEX-records/<CVE> --pin
# conformance check:
python3 tools/cvex_check.py CVEX-records/<CVE>
```

These are the records to start from when authoring a new one, demonstrating the
format, or validating a change to the tooling.
