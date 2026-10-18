#!/usr/bin/env python3
"""
genie_stackharness.py <go|c> <cve-list-file>

Apply a per-stack reproduction harness to genie src-tier records, mirroring the
manual successes (golang-jwt, editorconfig-core-c): toolchain image + vendored
source + run the carried verifier.py from the repo root.

  go : golang image + python3; verifier runs from the module (repo) root.
  c  : build-essential + cmake + common -dev libs; best-effort build (cmake /
       autotools / make), collect built libs into ./lib, run verifier from root.

Only touches unlocked records. Does not run anything (use tools/cvex_batch.sh).
"""
import json, sys
from pathlib import Path

def _work_root():
    """Directory that contains CVEX-records/ (search upward from CWD, then from this file)."""
    for base in (Path.cwd(), Path(__file__).resolve().parent):
        d = base
        while True:
            if (d / "CVEX-records").is_dir():
                return d
            if d.parent == d:
                break
            d = d.parent
    return Path(__file__).resolve().parent.parent
ROOT = _work_root()
RECS = ROOT / "CVEX-records"

GO = """# CVE-Genie reproduction (Go harness). verifier.py runs from the module root.
FROM golang:1.23-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends python3 strace unzip ca-certificates \\
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
{fetch}
COPY work/exploit.py work/verifier.py /work/{repo}/
RUN cd /work/{repo} && (go mod download 2>/dev/null || true)
COPY attack.sh /attack.sh
COPY benign.sh /benign.sh
RUN chmod +x /attack.sh /benign.sh
CMD ["sh","-c","sleep infinity"]
"""

C = """# CVE-Genie reproduction (C/C++ harness). Best-effort build, verifier from root.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \\
    build-essential cmake pkg-config git unzip strace python3 ca-certificates \\
    libpcre2-dev libpcre3-dev zlib1g-dev libssl-dev libcurl4-openssl-dev \\
    libexpat1-dev libxml2-dev libjpeg-dev libpng-dev \\
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
{fetch}
WORKDIR /work/{repo}
# best-effort build: cmake, else autotools, else make
RUN set -e; \\
    if [ -f CMakeLists.txt ]; then cmake . >/dev/null 2>&1 && make -j4 >/dev/null 2>&1 || true; \\
    elif [ -x ./configure ] || [ -f configure ]; then ./configure >/dev/null 2>&1 && make -j4 >/dev/null 2>&1 || true; \\
    elif [ -f Makefile ] || [ -f makefile ]; then make -j4 >/dev/null 2>&1 || true; fi; \\
    mkdir -p lib; \\
    find . -name '*.a' -exec cp {} lib/ \\; 2>/dev/null || true; \\
    find . -name '*.so*' -exec cp {} lib/ \\; 2>/dev/null || true; \\
    true
COPY work/exploit.py work/verifier.py /work/{repo}/
COPY attack.sh /attack.sh
COPY benign.sh /benign.sh
RUN chmod +x /attack.sh /benign.sh
CMD ["sh","-c","sleep infinity"]
"""

def fetch(url):
    return (f"ADD {url} /work/src.zip\nRUN unzip -q src.zip && rm src.zip"
            if url else "# TODO: no source URL in cve_info")

def apply(cve, stack):
    rec = RECS / cve
    if (rec / ".cvex-lock").exists():
        return "locked"
    info = {}
    ij = rec / "_source" / "cve_info.json"
    if ij.exists():
        try: info = json.loads(ij.read_text())
        except Exception: pass
    url = info.get("sw_version_wget", "")
    repo = (info.get("repo_path") or "").strip("/")
    tmpl = GO if stack == "go" else C
    (rec / "target" / "Dockerfile").write_text(tmpl.format(fetch=fetch(url), repo=repo))
    (rec / "target" / "attack.sh").write_text(f"#!/bin/sh\ncd /work/{repo} && python3 verifier.py\n")
    (rec / "target" / "attack.sh").chmod(0o755)
    (rec / "target" / "benign.sh").write_text(
        f"#!/bin/sh\ncd /work/{repo} && echo 'benign: normal use (placeholder)'\n")
    (rec / "target" / "benign.sh").chmod(0o755)
    return "applied"

def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("go", "c"):
        print("usage: genie_stackharness.py <go|c> <cve-list-file>"); sys.exit(1)
    stack = sys.argv[1]
    cves = [l.split("\t")[0].strip() for l in Path(sys.argv[2]).read_text().splitlines() if l.strip()]
    r = {}
    for c in cves:
        s = apply(c, stack); r[s] = r.get(s, 0) + 1
    print(f"{stack} harness applied:", r)

if __name__ == "__main__":
    main()
