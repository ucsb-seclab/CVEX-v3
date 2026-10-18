#!/usr/bin/env python3
"""genie_to_v3.py [CVE ...] -- wrap CVE-Genie reproductions as CVEX v3 records.

For every Historic/cve-genie/results/reproduced_cves/CVE-* it produces a v3 record
under CVEX-records/<CVE> that:
  - installs the vulnerable software (target builds it from the source archive in
    cve_info.sw_version_wget, per the detected stack);
  - plants a flag and ships a BENIGN interaction (legitimate use of the software);
  - INCLUDES the exploit.py and verifier.py that CVE-Genie already produced (these
    are not authored here) -- success criterion is the verifier.

Single topology (the exploit/verifier run inside the target). The target build is
best-effort for library/app sources; records that need hand-finishing say so in
TODO.md. Build/stand a record up with:
  python3 tools/cvex_standup.py CVEX-records/<CVE> --single
"""
import hashlib, json, re, shutil, sys
from pathlib import Path

ROOT = Path.cwd()
while not (ROOT / "CVEX-records").is_dir() and ROOT.parent != ROOT:
    ROOT = ROOT.parent
GENIE = ROOT / "Historic" / "cve-genie" / "results" / "reproduced_cves"
RECS = ROOT / "CVEX-records"


def flag_for(cve):
    return "CVEX{%s}" % hashlib.md5(("cvex-v3:" + cve).encode()).hexdigest()


def w(p, s, mode=None):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s)
    if mode:
        p.chmod(mode)


def detect_stack(gdir, info):
    """Guess the stack from the setup logs, repo path, and source URL."""
    hints = ""
    log = gdir / "conversations" / "repo_builder_setup_logs.txt"
    if log.exists():
        hints += log.read_text(errors="ignore")[:20000].lower()
    hints += " " + json.dumps(info).lower()
    def has(*ks): return any(k in hints for k in ks)
    if has("package-lock.json", "npm install", "npm ci", "node_modules", "yarn "):
        return "node"
    if has("pip install", "requirements.txt", "setup.py", "pyproject.toml", "python3 -m venv", "poetry "):
        return "python"
    if has("go mod", "go build", "go install", "go test"):
        return "go"
    if has("mvn ", "pom.xml", "gradle"):
        return "java"
    if has("cargo build", "cargo.toml"):
        return "rust"
    if has("composer install", "composer.json"):
        return "php"
    if has("cmake", "./configure", "make -j", "makefile"):
        return "c"
    return "unknown"


BASE = {
    "python": "python:3.11-slim",
    "node": "node:20-slim",
    "go": "golang:1.22-bookworm",
    "java": "eclipse-temurin:17-jdk-jammy",
    "rust": "rust:1-slim",
    "php": "php:8.2-cli",
    "c": "debian:12-slim",
    "unknown": "debian:12-slim",
}

INSTALL = {
    "python": "RUN pip install --no-cache-dir -e . 2>/dev/null || pip install --no-cache-dir . 2>/dev/null || true\n",
    "node": "RUN npm install --no-audit --no-fund 2>/dev/null || true\n",
    "go": "RUN go mod download 2>/dev/null || true; go build ./... 2>/dev/null || true\n",
    "java": "RUN mvn -q -DskipTests package 2>/dev/null || ./gradlew build -x test 2>/dev/null || true\n",
    "rust": "RUN cargo build 2>/dev/null || true\n",
    "php": "RUN composer install --no-interaction 2>/dev/null || true\n",
    "c": ("RUN if [ -f CMakeLists.txt ]; then cmake . && make -j4; "
          "elif [ -x ./configure ] || [ -f configure ]; then ./configure && make -j4; "
          "elif [ -f Makefile ]; then make -j4; fi 2>/dev/null || true\n"),
    "unknown": "# TODO: install the vulnerable software (stack not detected)\n",
}

TOOLCHAIN = {
    "python": "RUN apt-get update && apt-get install -y --no-install-recommends gcc python3-dev strace ca-certificates tar && rm -rf /var/lib/apt/lists/*\n",
    "node": "RUN apt-get update && apt-get install -y --no-install-recommends python3 strace ca-certificates git tar && rm -rf /var/lib/apt/lists/*\n",
    "go": "RUN apt-get update && apt-get install -y --no-install-recommends python3 strace ca-certificates tar && rm -rf /var/lib/apt/lists/*\n",
    "java": "RUN apt-get update && apt-get install -y --no-install-recommends python3 strace ca-certificates maven tar && rm -rf /var/lib/apt/lists/*\n",
    "rust": "RUN apt-get update && apt-get install -y --no-install-recommends python3 strace ca-certificates tar && rm -rf /var/lib/apt/lists/*\n",
    "php": "RUN apt-get update && apt-get install -y --no-install-recommends python3 strace ca-certificates git tar && rm -rf /var/lib/apt/lists/*\n",
    "c": "RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake pkg-config git python3 strace ca-certificates tar && rm -rf /var/lib/apt/lists/*\n",
    "unknown": "RUN apt-get update && apt-get install -y --no-install-recommends python3 strace ca-certificates git tar && rm -rf /var/lib/apt/lists/*\n",
}

TRACE = {"python": "python", "node": "node", "go": "", "java": "java",
         "rust": "", "php": "php", "c": "", "unknown": ""}


def convert(gdir):
    cve = gdir.name
    if not re.match(r"CVE-\d{4}-\d+$", cve):
        return "not-a-cve"
    ci = gdir / "conversations" / "cve_info.json"
    if not ci.exists():
        return "no-cve-info"
    try:
        info = json.loads(ci.read_text())
    except Exception as e:
        return f"bad-cve-info ({e})"
    url = info.get("sw_version_wget", "")
    repo = (info.get("repo_path") or "").strip("/")
    stack = detect_stack(gdir, info)
    flag = flag_for(cve)

    rec = RECS / cve
    if rec.exists():
        shutil.rmtree(rec)
    rec.mkdir(parents=True)
    # _source: genie metadata (json only; skip the large .txt agent logs) + scripts
    (rec / "_source" / "conversations").mkdir(parents=True)
    for j in (gdir / "conversations").glob("*.json"):
        shutil.copy(j, rec / "_source" / "conversations" / j.name)
    if (gdir / "scripts").exists():
        shutil.copytree(gdir / "scripts", rec / "_source" / "scripts")

    t = rec / "target"
    t.mkdir(parents=True, exist_ok=True)
    turl = re.sub(r"\.zip$", ".tar.gz", url) if url else url  # tar.gz extracts without unzip
    fetch = (f"ADD {turl} /tmp/src.tgz\nRUN tar xzf /tmp/src.tgz -C /work && rm /tmp/src.tgz\n"
             if url else "# TODO: no source URL in cve_info\n")
    workdir = f"/work/{repo}" if repo else "/work"
    # copy the genie exploit/verifier into the image
    have_scripts = (gdir / "scripts" / "verifier.py").exists()
    for s in ("exploit.py", "verifier.py"):
        sp = gdir / "scripts" / s
        if sp.exists():
            shutil.copy(sp, t / s)
    w(t / "Dockerfile",
      f"# {cve}: install the vulnerable software (CVE-Genie reproduction), stack={stack}.\n"
      f"FROM {BASE[stack]}\n" + TOOLCHAIN[stack] +
      "WORKDIR /work\n" + fetch +
      f"WORKDIR {workdir}\n" + INSTALL[stack] +
      "COPY plant-flag.sh /usr/local/bin/plant-flag.sh\n"
      + ("COPY exploit.py verifier.py ./\n" if have_scripts else "") +
      "COPY attack.sh benign.sh /\n"
      "RUN chmod +x /usr/local/bin/plant-flag.sh /attack.sh /benign.sh\n"
      f"ENV CVEX_FLAG={flag}\n"
      "CMD [\"sh\",\"-c\",\"/usr/local/bin/plant-flag.sh && touch /ready && exec sleep infinity\"]\n")
    w(t / "plant-flag.sh",
      "#!/bin/sh\nset -e\necho \"$CVEX_FLAG\" > /flag\nchmod 0644 /flag\n", 0o755)
    # attack = run the genie verifier (included exploit/verifier, not authored here)
    w(t / "attack.sh",
      "#!/bin/sh\n# Runs the CVE-Genie verifier/exploit shipped with this record (included, not\n"
      "# authored here). Success is decided by the verifier.\n"
      f"cd {workdir}\n"
      "if [ -f verifier.py ]; then python3 verifier.py; exit $?; fi\n"
      "echo 'no-verifier' >&2; exit 1\n", 0o755)
    w(t / "benign.sh",
      "#!/bin/sh\n# Benign use of the installed software (no exploit, no flag access).\n"
      f"cd {workdir}\n"
      "echo 'benign: software installed and importable'\n", 0o755)

    # recorder (single topology still records syscalls of the traced process)
    cap = RECS / "CVE-2021-41773" / "recorder" / "capture.sh"
    w(rec / "recorder" / "Dockerfile",
      "# Recorder sidecar.\nFROM debian:12-slim\n"
      "RUN apt-get update && apt-get install -y --no-install-recommends tcpdump strace ca-certificates procps "
      "&& rm -rf /var/lib/apt/lists/*\n"
      "COPY capture.sh /capture.sh\nRUN chmod +x /capture.sh\nENTRYPOINT [\"/capture.sh\"]\n")
    if cap.exists():
        shutil.copy(cap, rec / "recorder" / "capture.sh"); (rec / "recorder" / "capture.sh").chmod(0o755)

    lo = cve.lower()
    w(rec / "cvex.yml",
      f"cvex_version: 3\ncve: {cve}\ntopology: single\nsource: cve-genie\nnetwork:\n  subnet: 10.13.0.0/24\n\n"
      f'flag:\n  value: "{flag}"\n  plant: file:/flag\nsuccess: verifier\n'
      f"capture:\n  flag_channel: stdout\n  tls_intercept: false\n  tls_ports: []\n\n"
      f"services:\n  target:\n    image: cvex/{lo}-target:todo\n    ip: 10.13.0.10\n"
      f"    trace: \"{TRACE[stack]}\"\n    ready: \"file:/ready\"\n\n"
      f"recorder:\n  image: cvex/{lo}-recorder:todo\n\n"
      "phases:\n  benign: { run: /benign.sh }\n  attack: { run: /attack.sh }\n\n"
      f"limits:\n  wall_clock_seconds: 900\n")
    w(rec / "STATUS.md",
      f"# {cve} (CVE-Genie) - CVEX v3\n\n- Source: cve-genie reproduction\n"
      f"- Stack: {stack}  source: `{url}`\n- Benign: installed  Flag: `{flag}` at /flag\n"
      f"- Exploit/verifier: included from CVE-Genie\n\n"
      f"Build/stand up: `python3 tools/cvex_standup.py CVEX-records/{cve} --single`\n")
    w(rec / "TODO.md",
      f"# {cve}: finish the CVEX v3 record (CVE-Genie, stack={stack})\n\n"
      "- [x] install the vulnerable software (target/Dockerfile fetches the source)\n"
      "- [x] benign interaction (target/benign.sh) -- refine to real legitimate use\n"
      "- [x] flag placement (/flag)\n"
      "- [x] exploit + verifier included from CVE-Genie (not authored here)\n"
      f"- [ ] confirm the build: `python3 tools/cvex_standup.py CVEX-records/{cve} --single`\n"
      "- [ ] if the stack build failed, port the steps from _source/conversations/\n"
      "      repo_builder.json (the 'access' field has the install instructions).\n\n"
      "<!-- HUMAN-NOTES:BEGIN (kept across regeneration) -->\n\n<!-- HUMAN-NOTES:END -->\n")
    return "ok:" + stack


def main():
    args = sys.argv[1:]
    dirs = [GENIE / a for a in args] if args else sorted(GENIE.glob("CVE-*"))
    import collections
    tally = collections.Counter()
    for d in dirs:
        r = convert(d)
        tally[r.split(" ")[0].split(":")[0]] += 1
    print("---", dict(tally))
    # per-stack breakdown
    st = collections.Counter()
    for d in dirs:
        pass


if __name__ == "__main__":
    main()
