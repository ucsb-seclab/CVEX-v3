#!/usr/bin/env python3
"""migrate_to_v3.py [CVE ...] -- scaffold gen-3 (Vagrant/Ansible) CVEX records into v3.

Rebuilt after the Oct 2026 data-loss incident (the original predated the saved
session history). For each record under Historic/CVEX-records it produces a v3
record under CVEX-records with the uniform shape (see CVEX_v3_DESIGN.md):

  _source/      verbatim copy of the gen-3 record (cvex.yml, playbooks, data/)
  target/       Dockerfile (TEMPLATE), vendor/ (data/ artifacts), plant-flag.sh
  benign/ attacker/ recorder/   Dockerfiles + capture.sh + stub scripts
  cvex.yml      v3 manifest (flag, topology, channel) with TODO image pins
  STATUS.md TODO.md

The exploit (attacker/exploit.sh or target/attack.sh), the real vulnerable build,
and the benign workload are left as TODO for a human: this is a faithful scaffold,
not a runnable record. The 10 "gold" records are produced by conform10.py instead
and are skipped here unless explicitly named.

Topology is taken from the gen-3 `blueprint` (one host -> single, two -> target-
attacker). Class/flag/channel/trace defaults come from the embedded CORPUS table
(derived from CVEX_v3/CVEX_CORPUS_STATUS.md).
"""
import hashlib, shutil, sys, yaml
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
HIST = ROOT / "Historic" / "CVEX-records"
RECS = ROOT / "CVEX-records"

# produced by conform10.py -- do not scaffold over them unless explicitly named
GOLD = {"CVE-2014-7186", "CVE-2015-1427", "CVE-2017-12617", "CVE-2019-14287",
        "CVE-2021-41773", "CVE-2021-42013", "CVE-2023-22809", "CVE-2024-21532",
        "CVE-2024-21533", "CVE-2024-3660"}

# cve -> (class, plant, channel, trace, needs_db)
CORPUS = {
    "CVE-2014-6271":  ("RCE (Shellshock CGI)",      "file:/flag",            "network", "bash",   False),
    "CVE-2017-9805":  ("RCE (Struts REST XStream)", "file:/flag",            "network", "java",   False),
    "CVE-2018-20062": ("RCE (ThinkPHP)",            "file:/flag",            "network", "php",    False),
    "CVE-2018-9206":  ("upload -> RCE (jQuery File Upload)", "file:/flag",   "network", "php",    False),
    "CVE-2019-18276": ("privesc (bash setuid)",     "file:/root/flag:0600",  "stdout",  "bash",   False),
    "CVE-2020-16846": ("RCE (SaltStack)",           "file:/flag",            "network", "python", False),
    "CVE-2020-1938":  ("file read (Ghostcat AJP)",  "file:/opt/secret/flag", "network", "java",   False),
    "CVE-2020-5405":  ("file read (Spring Cloud Config)", "file:/opt/secret/flag", "network", "java", False),
    "CVE-2021-32682": ("RCE (elFinder)",            "file:/flag",            "network", "php",    False),
    "CVE-2021-34081": ("RCE (gitsome)",             "file:/flag",            "stdout",  "python", False),
    "CVE-2021-44228": ("RCE (Log4Shell)",           "file:/flag",            "network", "java",   False),
    "CVE-2022-22965": ("RCE (Spring4Shell)",        "file:/flag",            "network", "java",   False),
    "CVE-2024-6205":  ("RCE (WP PayPlus plugin)",   "file:/flag",            "network", "php",    True),
    "CVE-2024-9796":  ("SQLi (WP Advanced Search)", "file:/opt/secret/flag", "network", "php",    True),
}

CAPTURE_SH = (RECS / "CVE-2021-41773" / "recorder" / "capture.sh")  # canonical, from a gold record

OFFLINE_NOTE = ("# TODO make this build offline + digest-pinned (see the gold records and\n"
                "# CVEX_v3_DESIGN.md section 7): pin FROM by @sha256, vendor sources under\n"
                "# vendor/ with a SHA256SUMS, and build with docker build --network=none.\n")


def flag_for(cve):
    return "CVEX{%s}" % hashlib.md5(("cvex-v3:" + cve).encode()).hexdigest()


def w(p, s, mode=None):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s)
    if mode:
        p.chmod(mode)


def topology_of(src):
    try:
        y = yaml.safe_load((src / "cvex.yml").read_text()) or {}
    except Exception:
        y = {}
    bp = str(y.get("blueprint", ""))
    return "target-attacker" if bp.count("ubuntu") >= 2 or "-" in bp else "single"


def recorder(rec, trace):
    d = rec / "recorder"
    w(d / "Dockerfile",
      "# Recorder sidecar: tcpdump + strace, shares the target's net + PID namespaces.\n"
      "FROM debian:12-slim\n"
      "RUN apt-get update && apt-get install -y --no-install-recommends "
      "tcpdump strace ca-certificates procps && rm -rf /var/lib/apt/lists/*\n"
      "COPY capture.sh /capture.sh\nRUN chmod +x /capture.sh\nENTRYPOINT [\"/capture.sh\"]\n")
    if CAPTURE_SH.exists():
        shutil.copy(CAPTURE_SH, d / "capture.sh")
        (d / "capture.sh").chmod(0o755)


def client(rec, comp, script, benign):
    d = rec / comp
    what = "legitimate client" if benign else "attacker client"
    w(d / "Dockerfile",
      f"# The {what} (curl). TODO pin FROM by @sha256 and vendor curl for an offline build.\n"
      "FROM debian:12-slim\n"
      "RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates "
      "&& rm -rf /var/lib/apt/lists/*\n"
      f"COPY {script} /{script}\nRUN chmod +x /{script}\nENTRYPOINT [\"/{script}\"]\n")


def manifest(rec, cve, topo, flag, plant, channel, trace, port):
    lo = cve.lower()
    if topo == "single":
        phases = ("phases:                    # single topology: both phases run inside the target\n"
                  "  benign: { run: /benign.sh }\n"
                  "  attack: { run: /attack.sh }\n")
        ready = "file:/ready"
        svc_extra = ""
    else:
        phases = ("phases:\n"
                  "  benign:\n    client: benign             # runs benign/interact.sh\n"
                  f"    image: cvex/{lo}-benign:todo    # TODO pin by @sha256 digest\n    ip: 10.13.0.30\n"
                  "  attack:\n    client: attacker           # runs attacker/exploit.sh, must emit the flag\n"
                  f"    image: cvex/{lo}-attacker:todo    # TODO pin by @sha256 digest\n    ip: 10.13.0.20\n")
        ready = f"tcp:{port}"
        svc_extra = ""
    db = ("  db:                          # TODO: this record needs a database container\n"
          f"    image: cvex/{lo}-db:todo\n    ip: 10.13.0.11\n" if topo == "target+db-attacker" else "")
    w(rec / "cvex.yml",
      f"cvex_version: 3\ncve: {cve}\ntopology: {topo}\nnetwork:\n  subnet: 10.13.0.0/24\n\n"
      f'flag:\n  value: "{flag}"\n  plant: {plant}\nsuccess: flag\n'
      f"capture:\n  flag_channel: {channel}\n  tls_intercept: false\n  tls_ports: []\n\n"
      f"services:\n  target:\n    image: cvex/{lo}-target:todo    # TODO pin by @sha256 digest\n"
      f"    ip: 10.13.0.10\n    trace: {trace}\n    ready: \"{ready}\"\n{svc_extra}{db}\n"
      f"recorder:\n  image: cvex/{lo}-recorder:todo\n\n"
      f"{phases}\nlimits:\n  wall_clock_seconds: 600\n")


def status_todo(rec, cve, klass, topo, plant, channel):
    w(rec / "STATUS.md",
      f"# {cve} - v3 migration status\n\n"
      f"- Source: gen-3 (Vagrant/Ansible), preserved under `_source/`\n"
      f"- Class: {klass}\n- Topology: `{topo}`\n"
      f"- Flag: `{flag_for(cve)}`  plant `{plant}`  channel `{channel}`\n\n"
      "**Scaffold only** - not yet runnable. See `TODO.md`.\n")
    single = topo == "single"
    exploit = "target/attack.sh" if single else "attacker/exploit.sh"
    benign = "target/benign.sh" if single else "benign/interact.sh"
    w(rec / "TODO.md",
      f"# {cve}: bring this scaffold to a runnable CVEX v3 record\n\n"
      f"Class: **{klass}**. Topology: **{topo}**. Flag channel: **{channel}**.\n\n"
      "The gen-3 original is preserved in `_source/` (playbooks + `data/`); its\n"
      "exploit is a good starting point. To finish:\n\n"
      "- [ ] `target/Dockerfile`: build the vulnerable service from the vendored\n"
      "      sources in `target/vendor/` (ported from the Ansible playbook in\n"
      "      `_source/`). Pin `FROM` by `@sha256` and build offline (`--network=none`).\n"
      f"- [ ] `target/plant-flag.sh`: plant the flag at `{plant}` so only the\n"
      "      vulnerability can read it.\n"
      f"- [ ] `{exploit}`: perform the exploit and emit `CVEX_FLAG=<captured>`.\n"
      f"- [ ] `{benign}`: exercise the same surface benignly (no flag access).\n"
      + ("- [ ] add the database container the manifest notes (`topology: target+db-attacker`).\n"
         if topo == "target+db-attacker" else "") +
      "- [ ] `python3 tools/cvex_run.py CVEX-records/" + cve + " --pin` to build, run\n"
      "      both phases, capture the dataset, and verify the flag.\n"
      "- [ ] `python3 tools/cvex_check.py CVEX-records/" + cve + "` until it PASSes.\n\n"
      "<!-- HUMAN-NOTES:BEGIN (kept across regeneration) -->\n\n<!-- HUMAN-NOTES:END -->\n")


def migrate(cve):
    src = HIST / cve
    if not src.exists():
        print("skip (no source)", cve); return
    rec = RECS / cve
    # preserve human notes if re-running
    notes = ""
    todo = rec / "TODO.md"
    if todo.exists():
        t = todo.read_text()
        a, b = t.find("<!-- HUMAN-NOTES:BEGIN"), t.find("<!-- HUMAN-NOTES:END")
        if a != -1 and b != -1:
            notes = t[t.find("\n", a) + 1:b].strip("\n")
    if rec.exists():
        shutil.rmtree(rec)
    topo = topology_of(src)
    klass, plant, channel, trace, needs_db = CORPUS.get(
        cve, ("TODO classify", "file:/flag", "network", "TODO", False))
    if needs_db:
        topo = "target+db-attacker"
    flag = flag_for(cve)
    # _source = verbatim gen-3 record
    shutil.copytree(src, rec / "_source")
    # target: vendor the data/ artifacts, template Dockerfile + plant-flag
    (rec / "target" / "vendor").mkdir(parents=True)
    if (src / "data").exists():
        for f in (src / "data").iterdir():
            if f.is_file():
                shutil.copy(f, rec / "target" / "vendor" / f.name)
            elif f.is_dir():
                shutil.copytree(f, rec / "target" / "vendor" / f.name)
    (rec / "target" / "vendor" / ".gitkeep").touch()
    plant_path = plant.split(":")[1] if plant.startswith("file:") else "/flag"
    mode = "0600" if "0600" in plant else "0644"
    mk = ("mkdir -p \"$(dirname FLAGPATH)\"\n".replace("FLAGPATH", plant_path)
          if "/" in plant_path.strip("/") else "")
    w(rec / "target" / "plant-flag.sh",
      "#!/bin/sh\nset -e\n" + mk +
      f'echo "$CVEX_FLAG" > {plant_path}\nchmod {mode} {plant_path}\n', 0o755)
    w(rec / "target" / "Dockerfile",
      f"# {cve}: {klass}\n" + OFFLINE_NOTE +
      "# TODO: build the vulnerable service from the sources vendored in vendor/\n"
      "#       (port the steps from the Ansible playbook in _source/).\n"
      "FROM debian:12-slim\n"
      "COPY vendor/ /tmp/vendor/\n"
      "COPY plant-flag.sh /usr/local/bin/plant-flag.sh\n"
      "RUN chmod +x /usr/local/bin/plant-flag.sh\n"
      "ENV CVEX_FLAG=CVEX{placeholder}\n"
      + ("CMD [\"sh\",\"-c\",\"/usr/local/bin/plant-flag.sh && touch /ready && exec sleep infinity\"]\n"
         if topo == "single" else
         "# EXPOSE <port>\nCMD [\"sh\",\"-c\",\"/usr/local/bin/plant-flag.sh && exec sleep infinity  # TODO run the service\"]\n"))
    # phase scripts
    if topo == "single":
        w(rec / "target" / "attack.sh",
          f"#!/bin/sh\n# TODO: exploit {cve} and emit CVEX_FLAG=<captured>.\n"
          "echo 'exploit-failed (scaffold)' >&2\nexit 1\n", 0o755)
        w(rec / "target" / "benign.sh",
          "#!/bin/sh\n# TODO: exercise the same surface benignly (no flag access).\n"
          "echo 'benign (scaffold)'\n", 0o755)
    else:
        port = 80
        client(rec, "benign", "interact.sh", True)
        client(rec, "attacker", "exploit.sh", False)
        w(rec / "benign" / "interact.sh",
          '#!/bin/sh\nTARGET="${TARGET:-target}"; PORT="${PORT:-80}"\n'
          "# TODO: legitimate use of the same service/endpoints the attack touches.\n"
          'curl -s -o /dev/null -w "benign GET / -> %{http_code}\\n" "http://$TARGET:$PORT/" || true\n', 0o755)
        w(rec / "attacker" / "exploit.sh",
          '#!/bin/sh\nTARGET="${TARGET:-target}"; PORT="${PORT:-80}"\n'
          f"# TODO: exploit {cve}, capture the flag from {plant}, emit CVEX_FLAG=<captured>.\n"
          "echo 'exploit-failed (scaffold)' >&2\nexit 1\n", 0o755)
    recorder(rec, trace)
    manifest(rec, cve, topo, flag, plant, channel, trace, 80)
    status_todo(rec, cve, klass, topo, plant, channel)
    if notes:
        t = (rec / "TODO.md").read_text()
        t = t.replace("<!-- HUMAN-NOTES:BEGIN (kept across regeneration) -->\n\n",
                      "<!-- HUMAN-NOTES:BEGIN (kept across regeneration) -->\n" + notes + "\n")
        (rec / "TODO.md").write_text(t)
    print(f"scaffolded {cve}  topo={topo}  class={klass}")


def main():
    args = sys.argv[1:]
    if args:
        cves = args
    else:
        cves = sorted(d.name for d in HIST.glob("CVE-*") if d.name not in GOLD)
    for cve in cves:
        if cve in GOLD and cve not in args:
            continue
        migrate(cve)


if __name__ == "__main__":
    main()
