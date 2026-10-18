#!/usr/bin/env python3
"""
gen_todo.py [CVE ...]

Write a TODO.md into every record that is not yet fully functional, telling a
human what remains to turn it into a verified CVEX v3 record. The content is
derived from the record's current state (Dockerfile kind, setup/ hooks,
placeholders), the batch lists in tools/lists/, and, for CVE-Genie records, the
environment notes left by Genie's builder agents.

  - Covers CVEX-records/ (unlocked records) and CVEX_v3-unreproduced/.
  - Removes TODO.md from locked (functional) records.
  - Regenerated on every run; text between the HUMAN-NOTES markers is kept.

Does not build or run anything.
"""
import datetime, json, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RECS = ROOT / "CVEX-records"
QUAR = ROOT / "CVEX_v3-unreproduced"
GENIE = ROOT / "cve-genie" / "results" / "reproduced_cves"
LISTS = ROOT / "tools" / "lists"

NOTES_BEGIN = "<!-- HUMAN-NOTES:BEGIN (kept across regeneration) -->"
NOTES_END = "<!-- HUMAN-NOTES:END -->"

# Failed in the 2026-10-10 C batch and not yet triaged (see PROGRESS.md).
C_UNTRIAGED = {"CVE-2024-41672", "CVE-2024-43790", "CVE-2024-42358", "CVE-2024-47611",
               "CVE-2024-49369", "CVE-2024-51737", "CVE-2025-24356", "CVE-2025-31492",
               "CVE-2025-29769"}
BAZEL = {"CVE-2024-39305", "CVE-2024-53271"}  # envoy


def read_list(name):
    p = LISTS / name
    if not p.exists():
        return set()
    return {l.split("\t")[0].split()[0] for l in p.read_text().splitlines() if l.strip()}


def batch_results():
    """CVE -> SUCCESS/FAILED from the batch summary files (last one wins)."""
    res = {}
    for p in sorted(LISTS.glob("batch*.out")):
        for l in p.read_text().splitlines():
            m = re.match(r"(SUCCESS|FAILED)\s+(CVE-\d+-\d+)", l)
            if m:
                res[m.group(2)] = m.group(1)
    return res


def yml_field(text, key):
    m = re.search(rf"^\s*{key}:\s*(.+?)\s*(#.*)?$", text, re.M)
    return m.group(1).strip().strip('"') if m else ""


def load_json(p):
    try:
        return json.loads(p.read_text())
    except Exception:
        return {}


def top_level(dir_tree):
    """Names at depth 1 of a `tree` listing."""
    names = set()
    for l in dir_tree.splitlines():
        m = re.match(r"^[├└]── (.+)$", l)
        if m:
            names.add(m.group(1).strip())
    return names


def detect_stack(info):
    top = top_level(info.get("dir_tree", ""))
    checks = [("go", {"go.mod"}), ("rust", {"Cargo.toml"}), ("java", {"pom.xml", "build.gradle", "build.gradle.kts"}),
              ("php", {"composer.json"}), ("ruby", {"Gemfile"}), ("node", {"package.json"}),
              ("python", {"pyproject.toml", "setup.py", "setup.cfg", "requirements.txt"}),
              ("c", {"CMakeLists.txt", "configure", "configure.ac", "Makefile", "meson.build", "BUILD.bazel", "WORKSPACE"})]
    for name, files in checks:
        if top & files:
            return name
    return "unknown"


def dockerfile_kind(rec):
    df = rec / "target" / "Dockerfile"
    if not df.exists():
        return "missing"
    first = df.read_text().splitlines()[0] if df.read_text() else ""
    for key, kind in [("pip-installable", "pip"), ("Go harness", "go-harness"),
                      ("C/C++ harness", "c-harness"), ("Python source harness", "py-harness"),
                      ("build from source", "genie-scaffold"), ("Vulnerable service for", "migrated-scaffold")]:
        if key in first:
            return kind
    return "custom"


def quote(text, limit=1800):
    text = (text or "").strip()
    if len(text) > limit:
        text = text[:limit].rsplit("\n", 1)[0] + "\n…(truncated; see the source file)"
    return "\n".join("> " + l if l.strip() else ">" for l in text.splitlines())


def box(ok):
    return "[x]" if ok else "[ ]"


def old_notes(path):
    if not path.exists():
        return ""
    t = path.read_text()
    if NOTES_BEGIN in t and NOTES_END in t:
        return t.split(NOTES_BEGIN, 1)[1].split(NOTES_END, 1)[0].strip("\n")
    return ""


RUN_AND_LOCK = """## Definition of done
The record is fully functional when `tools/cvex_run.py` builds and runs it,
the verdict is `"success": true`, and `dataset/` holds benign + attack pcap and
syscall captures. The runner then writes `.cvex-lock` (never edit a locked
record by hand). Then:

```sh
python3 tools/cvex_run.py {path}          # build, run both phases, verify, lock
python3 tools/gen_todo.py {cve}           # removes this TODO.md once locked
```
and add the CVE to the Functional list in `CVEX-records/PROGRESS.md`.
Do not fabricate datasets: only a record verified by the runner counts.
"""


# --------------------------------------------------------------------------- genie

def genie_todo(rec, cve, ctx):
    yml = (rec / "cvex.yml").read_text()
    info = load_json(rec / "_source" / "cve_info.json")
    gdir = GENIE / cve / "conversations"
    builder = load_json(gdir / "repo_builder.json")
    prereq = load_json(gdir / "pre_req_builder.json")
    kind = dockerfile_kind(rec)
    stack = detect_stack(info)
    setup = rec / "target" / "setup"
    src_url = info.get("sw_version_wget") or yml_field(yml, "source")
    version = info.get("sw_version") or yml_field(yml, "sw_version")
    cwes = ", ".join(c.get("id", "") for c in info.get("cwe", [])) or "?"
    desc = re.sub(r"\s+", " ", info.get("description", "")).strip()
    benign = (rec / "target" / "benign.sh").read_text() if (rec / "target" / "benign.sh").exists() else ""
    benign_placeholder = "import" in benign and benign.count("\n") <= 3 or not benign.strip()
    pinned = ":todo" not in yml
    override = (rec / "target" / "source.override").exists()
    fixup = (setup / "fixup.sh").exists()
    quarantined = rec.parent == QUAR or (QUAR / cve).exists()

    # ---- status + next steps -------------------------------------------------
    steps = []
    if quarantined:
        status = ("**Quarantined: the vulnerable source can no longer be downloaded** "
                  f"(`{src_url}`). Canonical copy: `CVEX_v3-unreproduced/{cve}/`.")
        steps += [
            f"Find the exact vulnerable source ({version}). Try, in order: the parent of the patch "
            "commit listed in `_source/cve_info.json` (`patch_commits`), a fork or mirror of the repository, "
            "a package registry (npm/PyPI/Docker Hub) release of the same version.",
            "Record the replacement in `target/source.override` as JSON "
            '(`{"url": ..., "repo": ..., "why": ...}`) and re-apply the harness for the stack '
            f"(detected: **{stack}**).",
            "Stand up the environment described below, then run the record from `CVEX_v3-unreproduced/` and, "
            "once green, move it back to `CVEX-records/` (deleting the stale scaffold copy there).",
        ]
    elif cve in ctx["rerun"]:
        status = ("**Fixed by hand, awaiting re-run.** The fix was verified interactively inside the image "
                  "but the record has not been re-run by the runner.")
        steps += ["Run the runner (see *Definition of done*). If it passes, it locks itself; nothing else to do."]
    elif cve in ctx["bespoke"]:
        status = "**Needs a bespoke environment.** The generic harness cannot reproduce this record."
        steps += ["Read Genie's builder log (below) and write `target/Dockerfile` by hand for the services the verifier needs."]
    elif cve in BAZEL:
        status = "**Not attempted: Bazel build.** Left out of the C batch (envoy builds take hours and >30 GB)."
        steps += ["Use an upstream envoy release image of the vulnerable version instead of building from source, "
                  "or build once on a large machine and vendor the binary."]
    elif ctx["batch"].get(cve) == "FAILED" or cve in C_UNTRIAGED:
        status = ("**Harness applied, batch run FAILED, not yet triaged.** The run log was not kept "
                  "(it went to /tmp); re-run to see it.")
        steps += [
            f"Re-run with `python3 tools/cvex_run.py CVEX-records/{cve} 2>&1 | tee /tmp/run_{cve}.log` and read "
            "the build log (`/work/build.log`, `/work/replay.log` in the image) and the attack-output tail.",
            "Typical causes so far: the agents built against a different toolchain version; the agents installed "
            "dependencies the replay missed; a prebuilt binary or asset existed in Genie's tree but not in the "
            "source archive; the 2400 s batch timeout.",
            "Put the fix in `target/setup/fixup.sh` (runs after replay, never regenerated) rather than in the "
            "generated Dockerfile.",
        ]
    elif kind in ("go-harness", "c-harness", "py-harness"):
        status = f"**Harness applied ({kind}), not run yet.**"
        steps += ["Run the runner (see *Definition of done*); triage as above if it fails."]
    elif kind == "pip":
        status = ("**pip-tier scaffold (vulnerable package pinned from PyPI), not functional.** The pip harness "
                  "did not reproduce it; the verifier most likely needs a running service, extra system "
                  "packages, or a native build.")
        steps += [
            "Run the runner once to see why the verifier fails.",
            "Compare with the environment Genie's builder set up (below): start any service the verifier expects "
            "(from `target/setup/start.sh` or the image CMD), install missing system packages, set env vars.",
        ]
    else:
        status = "**Scaffold only: the target does not build the vulnerable software yet.**"
        harness = {"go": "python3 tools/genie_stackharness.py go <list>",
                   "c": "python3 tools/genie_stackharness.py c <list>",
                   "python": "python3 tools/genie_pyharness.py <list>"}.get(stack)
        if harness:
            steps += [f"Detected stack **{stack}**: put `{cve}` in a list file and apply `{harness}`; it rewrites "
                      "`target/Dockerfile` and replays the agents' setup into `target/setup/`. Then run the runner, "
                      "triaging failures as in the C/Go batches (see `CVEX-records/PROGRESS.md`)."]
        else:
            steps += [
                f"Detected stack **{stack}**: there is no generic harness yet. Write `target/Dockerfile` by hand: "
                "toolchain image, download/unpack the source below, build/install it as the builder log shows, "
                "copy `work/exploit.py` and `work/verifier.py` to where the verifier expects them.",
                "Generate `target/setup/{replay,start,env}.sh` from the agents' logs with `tools/genie_replay.py` "
                "(as `genie_stackharness.py` does) and run `replay.sh` in the Dockerfile.",
                "If the app needs a database or other service, switch `topology` in `cvex.yml` and add it.",
            ]
        steps += ["Run the runner (see *Definition of done*)."]

    if not quarantined:
        if benign_placeholder:
            steps.append("Replace the placeholder `target/benign.sh` with legitimate use of the same interface the "
                         "attack touches (same endpoints/functions, benign inputs). It must not print the flag.")
        if not pinned:
            steps.append("Pin the images in `cvex.yml` by `@sha256` digest once the record is green.")
        steps.append("Optional: vendor the source archive into `target/vendor/` so the build does not download it.")

    # ---- checklist -----------------------------------------------------------
    built = kind in ("pip", "go-harness", "c-harness", "py-harness", "custom")
    checks = [
        (built, "`target/Dockerfile` installs/builds the vulnerable software"),
        (setup.exists(), "agents' environment replayed into `target/setup/` (replay/start/env)"),
        (not benign_placeholder, "`target/benign.sh` is a real benign workload (not a placeholder)"),
        ((rec / "target" / "work" / "verifier.py").exists(), "`verifier.py` + `exploit.py` carried in `target/work/`"),
        (pinned, "images pinned by digest"),
        ((rec / "dataset" / "verdict.json").exists(), "runner produced `dataset/` with a successful verdict"),
    ]

    # ---- environment notes from Genie ---------------------------------------
    env = []
    if builder.get("access"):
        env.append("**How Genie's builder agent made the target reachable** "
                   f"(`cve-genie/results/reproduced_cves/{cve}/conversations/repo_builder.json`, `access`):\n\n"
                   + quote(builder["access"]))
    if prereq.get("services"):
        env.append("**Services the setup needs** (`pre_req_builder.json`, `services`):\n\n" + quote(prereq["services"], 1200))

    path = f"CVEX_v3-unreproduced/{cve}" if rec.parent == QUAR else f"CVEX-records/{cve}"
    out = [f"# TODO: make {cve} a fully functional CVEX v3 record", "",
           f"_Generated by `tools/gen_todo.py` on {ctx['date']}. Regenerated automatically: put your own notes in "
           "the *Human notes* section at the bottom, which is preserved._", "",
           "## Record", "",
           f"- Origin: CVE-Genie reproduction (oracle: Genie's `verifier.py`, exit 0 == reproduced)",
           f"- Software: `{info.get('repo_path', '').strip('/') or '?'}`, version `{version}`, stack **{stack}**",
           f"- Source: {src_url}" + (" (overridden: see `target/source.override`)" if override else ""),
           f"- CWE: {cwes}",
           f"- Target image kind: `{kind}`" + ("; per-record `target/setup/fixup.sh` present" if fixup else ""),
           f"- Advisory summary: {desc[:400]}{'…' if len(desc) > 400 else ''}", "",
           "## Status", "", status, "",
           "## Checklist", ""] + [f"- {box(ok)} {t}" for ok, t in checks] + ["",
           "## Next steps", ""] + [f"{i}. {s}" for i, s in enumerate(steps, 1)] + [""]
    if env:
        out += ["## Environment the verifier expects", ""] + sum(([e, ""] for e in env), [])
    out += ["## Reference material", "",
            "- `_source/exploit.py`, `_source/verifier.py`: Genie's exploit and CTF-style verifier (the oracle).",
            "- `_source/cve_info.json`: advisory, CWE, patch commits, source URL and version, source tree.",
            f"- `cve-genie/results/reproduced_cves/{cve}/conversations/`: full agent logs; "
            "`repo_builder_setup_logs.txt` (every setup command the agents ran) and `exploiter_logs.txt` are the "
            "most useful.",
            "- `CVEX_v3_DESIGN.md`, `CVEX-records/PROGRESS.md`: format and the harness workflow.", "",
            RUN_AND_LOCK.format(path=path, cve=cve)]
    return out


# --------------------------------------------------------------------------- migrated

def migrated_todo(rec, cve, ctx):
    yml = (rec / "cvex.yml").read_text()
    status_md = (rec / "STATUS.md").read_text() if (rec / "STATUS.md").exists() else ""
    gen = re.search(r"Source generation: \*\*(\w)\*\* \(([^)]*\)?)\)", status_md)
    cls = re.search(r"Vulnerability class: `([^`]+)`", status_md)
    topo = yml_field(yml, "topology")
    success = yml_field(yml, "success")
    plant = yml_field(yml, "plant")
    channel = yml_field(yml, "flag_channel")
    trace = yml_field(yml, "trace")
    df = (rec / "target" / "Dockerfile").read_text() if (rec / "target" / "Dockerfile").exists() else ""
    single = topo == "single"
    ex_path = rec / ("target/attack.sh" if single else "attacker/exploit.sh")
    bn_path = rec / ("target/benign.sh" if single else "benign/interact.sh")
    ex = ex_path.read_text() if ex_path.exists() else ""
    bn = bn_path.read_text() if bn_path.exists() else ""
    vendor = [p.name for p in (rec / "target" / "vendor").glob("*") if p.name != ".gitkeep"] \
        if (rec / "target" / "vendor").exists() else []
    src_files = sorted(str(p.relative_to(rec)) for p in (rec / "_source").rglob("*") if p.is_file())
    df_done = "TODO: COPY vendored sources" not in df and bool(df)
    ex_done = bool(ex) and "TODO: capture the flag" not in ex
    has_carried = bool(re.search(r"^[^#\n].*\S", ex.split("original attack commands")[-1], re.M)) \
        if "original attack commands" in ex else False
    bn_done = bool(bn) and "TODO" not in bn
    trace_done = bool(trace) and "TODO" not in trace

    gen_letter = gen.group(1) if gen else "?"
    steps = []
    if not df_done:
        if gen_letter == "A":
            steps.append("Translate the original VM provisioning in `_source/` (`cvex.yml` + the Ansible "
                         "playbooks `*.yml`) into `target/Dockerfile`: install the same packages and configure the "
                         "service the same way, building the vulnerable software from the archives in "
                         "`_source/data/` (copy them into `target/vendor/`).")
        elif gen_letter == "C":
            steps.append("The source record only referenced a Docker Hub image (`_source/docker-compose.yml`). "
                         "Either pull that image by digest if it still exists, or rebuild the vulnerable version "
                         "of the software from upstream sources into `target/vendor/`.")
        else:
            steps.append("Build the vulnerable software in `target/Dockerfile` from the assets in `_source/`.")
        steps.append("Make sure `plant-flag.sh` runs at container start and the flag is placed "
                     f"at `{plant}` with permissions such that only the vulnerability can reach it.")
    if not ex_done:
        if has_carried:
            steps.append(f"Finish `{ex_path.relative_to(rec)}`: the original attack commands are carried over; "
                         "make the script retrieve the flag and print `CVEX_FLAG=<value>`"
                         + (" (the runner also searches the attack pcap, channel `network`)." if channel == "network" else "."))
        else:
            steps.append(f"Write `{ex_path.relative_to(rec)}`: no exploit existed in the source record. Base it on "
                         "the public advisory / a public proof of concept, and have it print `CVEX_FLAG=<value>`.")
    if not bn_done:
        steps.append(f"Write `{bn_path.relative_to(rec)}`: legitimate use of the same service and endpoints the "
                     "attack touches (normal requests, benign inputs). It must not reach the flag.")
    if not trace_done:
        steps.append("Set `services.target.trace` in `cvex.yml` to the process(es) to syscall-trace (regex), "
                     "and `ready` to a port (`tcp:N`) or file (`file:/ready`) condition.")
    steps.append("Run the runner (see *Definition of done*); pin images by `@sha256` digest once green.")

    checks = [
        (df_done, "`target/Dockerfile` builds the vulnerable software"),
        (bool(vendor), "vulnerable sources vendored in `target/vendor/`"),
        (ex_done, f"`{ex_path.relative_to(rec)}` retrieves and prints the flag"),
        (bn_done, f"`{bn_path.relative_to(rec)}` is a real benign workload"),
        (trace_done, "`trace` / `ready` set in `cvex.yml`"),
        (":todo" not in yml and "<digest>" not in yml, "images pinned by digest"),
        ((rec / "dataset" / "verdict.json").exists(), "runner produced `dataset/` with a successful verdict"),
    ]
    path = f"CVEX-records/{cve}"
    out = [f"# TODO: make {cve} a fully functional CVEX v3 record", "",
           f"_Generated by `tools/gen_todo.py` on {ctx['date']}. Regenerated automatically: put your own notes in "
           "the *Human notes* section at the bottom, which is preserved._", "",
           "## Record", "",
           f"- Origin: migrated from an earlier CVEX generation ({gen.group(2) if gen else 'see STATUS.md'})",
           f"- Vulnerability class: `{cls.group(1) if cls else '?'}`; topology `{topo}`",
           f"- Success criterion: `{success}`" + (f"; flag planted at `{plant}`, channel `{channel}`" if success == "flag" else ""),
           "", "## Status", "",
           "**Scaffold only: generated by `tools/migrate_to_v3.py`, never built or run.**", "",
           "## Checklist", ""] + [f"- {box(ok)} {t}" for ok, t in checks] + ["",
           "## Next steps", ""] + [f"{i}. {s}" for i, s in enumerate(steps, 1)] + ["",
           "## Reference material", ""] + [f"- `{f}`" for f in src_files[:25]] + \
          ([f"- …and {len(src_files) - 25} more under `_source/`"] if len(src_files) > 25 else []) + [
           "- A functional migrated record to copy from: `CVEX-records/CVE-2021-41773` (network, flag) or "
           "`CVEX-records/CVE-2023-22809` (local, flag).",
           "- `CVEX_v3_DESIGN.md` §2 (flag placement by class) and §4 (manifest).", "",
           RUN_AND_LOCK.format(path=path, cve=cve)]
    return out


# --------------------------------------------------------------------------- main

def write_todo(rec, ctx):
    cve = rec.name
    todo = rec / "TODO.md"
    if (rec / ".cvex-lock").exists():
        if todo.exists():
            todo.unlink()
            return "removed"
        return None
    yml = (rec / "cvex.yml").read_text() if (rec / "cvex.yml").exists() else ""
    lines = genie_todo(rec, cve, ctx) if "origin: cve-genie" in yml else migrated_todo(rec, cve, ctx)
    notes = old_notes(todo) or "_(none yet)_"
    lines += ["## Human notes", "", NOTES_BEGIN, notes, NOTES_END, ""]
    todo.write_text("\n".join(lines))
    return "written"


def main():
    ctx = {"date": datetime.date.today().isoformat(), "rerun": read_list("rerun.txt"),
           "bespoke": read_list("bespoke.txt"), "batch": batch_results()}
    wanted = set(sys.argv[1:])
    counts = {}
    for base in (RECS, QUAR):
        if not base.exists():
            continue
        for rec in sorted(base.glob("CVE-*")):
            if not rec.is_dir() or (wanted and rec.name not in wanted):
                continue
            r = write_todo(rec, ctx)
            if r:
                counts[r] = counts.get(r, 0) + 1
    print(" ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing to do")


if __name__ == "__main__":
    main()
