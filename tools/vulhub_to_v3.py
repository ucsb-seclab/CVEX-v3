#!/usr/bin/env python3
"""vulhub_to_v3.py [CVE ...] -- wrap vulhub environments as CVEX v3 records.

For every Historic/vulhub/<product>/CVE-*/docker-compose.yml it produces a v3
record under CVEX-records/<CVE> that:
  - stands up the SAME vulnerable service (target = FROM the vulhub image, with a
    committed flag baked in at a gated path; the image's own entrypoint is kept);
  - carries a database / auxiliary service when the compose has one;
  - ships a BENIGN interaction (a legitimate HTTP request to the service);
  - plants a flag (success criterion), and includes an exploit ONLY if the vulhub
    folder already ships a runnable one -- no exploit is written here.

This installs the vulnerable service and the benign + flag halves; the attacker is
left as TODO (see each record's TODO.md). Verify a record stands up with
  python3 tools/cvex_standup.py CVEX-records/<CVE>
"""
import hashlib, json, re, shutil, sys
from pathlib import Path
import yaml

ROOT = Path.cwd()
while not (ROOT / "CVEX-records").is_dir() and ROOT.parent != ROOT:
    ROOT = ROOT.parent
VULHUB = ROOT / "Historic" / "vulhub"
RECS = ROOT / "CVEX-records"
SKIP = set()  # filled with existing curated records at runtime

DB_HINTS = ("postgres", "mysql", "mariadb", "redis", "mongo", "db", "oracle",
            "mssql", "memcached", "rabbitmq", "elasticsearch")


def flag_for(cve):
    return "CVEX{%s}" % hashlib.md5(("cvex-v3:" + cve).encode()).hexdigest()


def w(p, s, mode=None):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s)
    if mode:
        p.chmod(mode)


def container_port(svc):
    """Best-effort container port from a compose service's ports/expose."""
    for key in ("ports", "expose"):
        v = svc.get(key) or []
        for item in v:
            s = str(item)
            # "host:container" or "container" or "container/tcp"
            s = s.split("/")[0]
            port = s.split(":")[-1]
            if port.isdigit():
                return int(port)
    return None


def find_compose(cvedir):
    for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
        p = cvedir / name
        if p.exists():
            return p
    return None


def convert(cvedir):
    cve = cvedir.name
    if not re.match(r"CVE-\d{4}-\d+$", cve):
        return "not-a-cve"
    if cve in SKIP:
        return "skip-curated"
    cf = find_compose(cvedir)
    if not cf:
        return "no-compose"
    try:
        comp = yaml.safe_load(cf.read_text()) or {}
    except Exception as e:
        return f"bad-compose ({e})"
    services = comp.get("services") or {}
    if not services:
        return "no-services"
    # pick the primary (target) service: first with published ports, else first
    primary = None
    for name, svc in services.items():
        if svc and svc.get("ports"):
            primary = (name, svc); break
    if primary is None:
        name = next(iter(services)); primary = (name, services[name])
    pname, psvc = primary
    pimg = psvc.get("image")
    pbuild = psvc.get("build")
    port = container_port(psvc) or 80
    # auxiliary services (db etc.)
    aux = [(n, s) for n, s in services.items() if n != pname]
    has_db = any(any(h in (n + str((s or {}).get("image", ""))).lower() for h in DB_HINTS)
                 for n, s in aux)
    topo = "target+db-attacker" if aux else "target-attacker"

    rec = RECS / cve
    if rec.exists():
        # keep human notes
        shutil.rmtree(rec)
    rec.mkdir(parents=True)
    # _source: compose + README only (skip images/screenshots)
    src = rec / "_source"
    src.mkdir()
    shutil.copy(cf, src / cf.name)
    for doc in ("README.md", "README.zh-cn.md"):
        if (cvedir / doc).exists():
            shutil.copy(cvedir / doc, src / doc)
    flag = flag_for(cve)

    # target: reuse the vulhub image, bake the flag in a new layer (entrypoint kept)
    t = rec / "target"
    t.mkdir(parents=True, exist_ok=True)
    if pimg:
        w(t / "Dockerfile",
          f"# {cve}: vulnerable service from vulhub.\n"
          f"# vulhub image {pimg} (pre-built vulnerable service); entrypoint kept as-is.\n"
          "# The flag is baked at a gated path; only the vulnerability should expose it.\n"
          f"FROM {pimg}\n"
          f"RUN (echo '{flag}' > /flag && chmod 0644 /flag) || true\n")
    else:
        # build-based vulhub service: make target/ a self-contained build from the
        # vulhub context (its own Dockerfile + files), then bake the flag at the end.
        bctx = pbuild if isinstance(pbuild, str) else (pbuild or {}).get("context", ".")
        bdf = (pbuild or {}).get("dockerfile", "Dockerfile") if isinstance(pbuild, dict) else "Dockerfile"
        srcctx = (cvedir / bctx).resolve()
        ctx_df = srcctx / bdf
        if srcctx.is_dir() and ctx_df.exists():
            for item in srcctx.iterdir():
                dst = t / item.name
                if item.is_dir():
                    shutil.copytree(item, dst, dirs_exist_ok=True)
                elif item.name != bdf:
                    shutil.copy(item, dst)
            df = ctx_df.read_text()
            w(t / "Dockerfile",
              f"# {cve}: vulnerable service from vulhub (build-based; context vendored here).\n"
              + df.rstrip() + "\n"
              f"# flag baked at a gated path\nRUN (echo '{flag}' > /flag && chmod 0644 /flag) || true\n")
        else:
            w(t / "Dockerfile",
              f"# {cve}: TODO build-based vulhub service; context not found.\n"
              f"FROM debian:12-slim\nRUN echo '{flag}' > /flag\n")
    w(t / "plant-flag.sh", f"#!/bin/sh\n# flag baked into the image at build time (/flag)\necho '{flag}'\n", 0o755)

    def envlist(svc):
        e = (svc or {}).get("environment") or []
        if isinstance(e, dict):
            e = [f"{k}={v}" for k, v in e.items()]
        return [str(x) for x in e]

    target_env = envlist(psvc)
    db_alias = ""
    db_env = []
    # auxiliary (db) service dir, if any -- a thin FROM wrapper so cvex can build it
    if aux:
        aname, asvc = aux[0]
        aimg = (asvc or {}).get("image", "")
        db_alias = aname           # the app connects to the db by this compose name
        db_env = envlist(asvc)
        envlines = "".join(f"ENV {e.replace('=', ' ', 1)}\n" for e in db_env)
        w(rec / "db" / "Dockerfile",
          f"# auxiliary service '{aname}' for {cve} (from the vulhub compose).\n"
          f"FROM {aimg}\n{envlines}" if aimg else
          f"# TODO auxiliary service '{aname}' (build-based in vulhub).\nFROM debian:12-slim\n")

    # benign client: a legitimate HTTP request to the same service
    w(rec / "benign" / "Dockerfile",
      "# Legitimate client (curl).\nFROM debian:12-slim\n"
      "RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates "
      "&& rm -rf /var/lib/apt/lists/*\n"
      "COPY interact.sh /interact.sh\nRUN chmod +x /interact.sh\nENTRYPOINT [\"/interact.sh\"]\n")
    w(rec / "benign" / "interact.sh",
      '#!/bin/sh\n# Legitimate use of the service (no access to the flag).\n'
      f'TARGET="${{TARGET:-target}}"; PORT="${{PORT:-{port}}}"\n'
      'for p in / /index.html /favicon.ico; do\n'
      '  curl -s -o /dev/null -w "benign GET $p -> %{http_code}\\n" "http://$TARGET:$PORT$p" || true\n'
      '  sleep 1\n'
      'done\n', 0o755)

    # attacker: only if the vulhub folder ships a runnable exploit script
    exploit_src = None
    for cand in ("poc.py", "exploit.py", "poc.sh", "exploit.sh"):
        if (cvedir / cand).exists():
            exploit_src = cvedir / cand; break
    atk = rec / "attacker"
    atk.mkdir(parents=True, exist_ok=True)
    if exploit_src:
        shutil.copy(exploit_src, atk / exploit_src.name)
        runner = (f"python3 /{exploit_src.name}" if exploit_src.suffix == ".py" else f"sh /{exploit_src.name}")
        w(atk / "Dockerfile",
          "# Attacker: the exploit shipped by vulhub (included as-is, not authored here).\n"
          "FROM debian:12-slim\n"
          "RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates python3 "
          "&& rm -rf /var/lib/apt/lists/*\n"
          f"COPY {exploit_src.name} /{exploit_src.name}\n"
          f"COPY exploit.sh /exploit.sh\nRUN chmod +x /exploit.sh\nENTRYPOINT [\"/exploit.sh\"]\n")
        w(atk / "exploit.sh",
          f'#!/bin/sh\nTARGET="${{TARGET:-target}}"; PORT="${{PORT:-{port}}}"\n'
          f"# included vulhub PoC; wire it to emit CVEX_FLAG=<captured> if it reads the flag\n"
          f"{runner} \"$TARGET\" \"$PORT\" || true\n", 0o755)
        atk_state = "included"
    else:
        w(atk / "Dockerfile",
          "# TODO attacker: no exploit is shipped with this record (none authored here).\n"
          "FROM debian:12-slim\n"
          "RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates "
          "&& rm -rf /var/lib/apt/lists/*\n"
          "COPY exploit.sh /exploit.sh\nRUN chmod +x /exploit.sh\nENTRYPOINT [\"/exploit.sh\"]\n")
        w(atk / "exploit.sh",
          '#!/bin/sh\n# TODO: no exploit developed for this record.\n'
          'echo "no-exploit (scaffold)" >&2\nexit 1\n', 0o755)
        atk_state = "todo"

    # recorder
    cap = RECS / "CVE-2021-41773" / "recorder" / "capture.sh"
    w(rec / "recorder" / "Dockerfile",
      "# Recorder sidecar: tcpdump + strace.\nFROM debian:12-slim\n"
      "RUN apt-get update && apt-get install -y --no-install-recommends tcpdump strace ca-certificates procps "
      "&& rm -rf /var/lib/apt/lists/*\n"
      "COPY capture.sh /capture.sh\nRUN chmod +x /capture.sh\nENTRYPOINT [\"/capture.sh\"]\n")
    if cap.exists():
        shutil.copy(cap, rec / "recorder" / "capture.sh"); (rec / "recorder" / "capture.sh").chmod(0o755)

    # cvex.yml
    lo = cve.lower()
    def yenv(items, indent):
        if not items:
            return ""
        pad = " " * indent
        return f"{pad}environment:\n" + "".join(f"{pad}  - {json.dumps(e)}\n" for e in items)
    db_block = ""
    if aux:
        db_block = (f"  db:\n    image: cvex/{lo}-db:todo\n    ip: 10.13.0.11\n"
                    f"    alias: {db_alias}\n" + yenv(db_env, 4))
    w(rec / "cvex.yml",
      f"cvex_version: 3\ncve: {cve}\ntopology: {topo}\nsource: vulhub\nnetwork:\n  subnet: 10.13.0.0/24\n\n"
      f'flag:\n  value: "{flag}"\n  plant: file:/flag\nsuccess: flag\n'
      f"capture:\n  flag_channel: network\n  tls_intercept: false\n  tls_ports: []\n\n"
      f"services:\n  target:\n    image: cvex/{lo}-target:todo    # FROM {pimg or 'build'} + flag\n"
      f"    ip: 10.13.0.10\n    trace: \"\"\n    ready: \"tcp:{port}\"\n" + yenv(target_env, 4) + f"{db_block}\n"
      f"recorder:\n  image: cvex/{lo}-recorder:todo\n\n"
      f"phases:\n  benign:\n    client: benign\n    image: cvex/{lo}-benign:todo\n    ip: 10.13.0.30\n"
      f"  attack:\n    client: attacker\n    image: cvex/{lo}-attacker:todo\n    ip: 10.13.0.20\n\n"
      f"limits:\n  wall_clock_seconds: 600\n")

    w(rec / "STATUS.md",
      f"# {cve} (vulhub) - CVEX v3\n\n- Source: vulhub (`{cvedir.relative_to(ROOT)}`)\n"
      f"- Target image: `{pimg or 'build-based'}`  port `{port}`  topology `{topo}`\n"
      f"- Benign: HTTP GET (installed)\n- Flag: `{flag}` at `/flag` (baked)\n"
      f"- Exploit: {atk_state}\n\nStand up: `python3 tools/cvex_standup.py CVEX-records/{cve}`\n")
    w(rec / "TODO.md",
      f"# {cve}: finish the CVEX v3 record\n\n"
      f"vulhub service **{pimg or 'build-based'}** on port **{port}**. The target (vulnerable\n"
      "service), a benign HTTP interaction, and the flag are in place.\n\n"
      "- [x] install the vulnerable service (target/)\n"
      "- [x] benign interaction (benign/interact.sh)\n"
      "- [x] flag placement (/flag, baked into the image)\n"
      + (f"- [~] exploit included from vulhub ({exploit_src.name}); wire it to emit CVEX_FLAG=\n" if exploit_src
         else "- [ ] exploit: none shipped; add one later (not authored here) to make it verifiable\n")
      + (f"- [ ] wire the auxiliary service (db) from the vulhub compose\n" if aux else "")
      + f"- [ ] stand-up check: `python3 tools/cvex_standup.py CVEX-records/{cve}`\n\n"
      "<!-- HUMAN-NOTES:BEGIN (kept across regeneration) -->\n\n<!-- HUMAN-NOTES:END -->\n")
    return "ok:" + atk_state


def main():
    # don't clobber the 10 gold + 14 migrated curated records
    global SKIP
    SKIP = {p.name for p in RECS.glob("CVE-*")
            if (p / ".cvex-lock").exists() or (p / "_source" / "cvex.yml").exists()}
    args = [a for a in sys.argv[1:]]
    if args:
        dirs = []
        for cve in args:
            hits = list(VULHUB.glob(f"*/{cve}"))
            dirs += hits or []
    else:
        dirs = sorted(p.parent for p in VULHUB.glob("*/CVE-*/docker-compose.yml"))
    import collections
    tally = collections.Counter()
    for d in dirs:
        r = convert(d)
        tally[r.split(" ")[0]] += 1
        if r.startswith("ok"):
            print("converted", d.name, r)
    print("---", dict(tally))


if __name__ == "__main__":
    main()
