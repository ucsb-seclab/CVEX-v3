#!/usr/bin/env python3
"""
cvex_check.py [--status] <record> [<record> ...]

Check CVEX v3 records against the format's conformance rules
(CVEX_v3_DESIGN.md sections 1-8). Does not build or run anything: run
tools/cvex_run.py first, then check what it produced.

  manifest  cvex.yml is complete and every image is pinned by @sha256 digest
  build     Dockerfiles use digest-pinned bases and fetch nothing at build time;
            every vendored file is covered by a matching SHA256SUMS
  content   real benign + attack workloads, flag planting, no TODO markers, no
            unused components
  dataset   a locked, successful verdict whose images match the pins, a clean
            benign phase, complete captures, and a MANIFEST.sha256 that verifies

--status rewrites each record's STATUS.md from the record and the check result.
Exit status 0 iff every record conforms.
"""
import hashlib, json, re, sys
from pathlib import Path
import yaml

DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
FLAG = re.compile(r"^CVEX\{[0-9a-f]{32}\}$")
SKIP = ("_source", "dataset", "_out", "vendor")
# build-time network access (anything not served from the vendored files)
NET = [
    (r"apt-get\s+(update|install)(?![^\n]*\./)", "apt-get from a mirror"),
    (r"\bapk\s+(add|update)\b", "apk from a mirror"),
    (r"\b(curl|wget)\b", "curl/wget download"),
    (r"\bgit\s+clone\s+\S*(https?|git|ssh)://", "git clone from the network"),
    (r"\bpip3?\s+install\b(?![^\n]*--no-index)", "pip install from an index"),
    (r"\bnpm\s+(install|i|ci)\b(?![^\n]*--offline)", "npm install from the registry"),
    (r"\b(yarn|pnpm)\s+(install|add)\b", "yarn/pnpm install"),
    (r"\bgo\s+(get|mod\s+download)\b", "go module download"),
    (r"\bcomposer\s+(install|require)\b", "composer install"),
    (r"^ADD\s+https?://", "ADD from a URL"),
]


def sha256(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def files(rec):
    for p in sorted(rec.rglob("*")):
        rel = p.relative_to(rec)
        if p.is_file() and not any(part in SKIP for part in rel.parts):
            yield p


def logical_lines(text):
    """Dockerfile lines with backslash continuations joined."""
    return re.sub(r"\\\n", " ", text).splitlines()


class Check:
    def __init__(self, rec):
        self.rec = Path(rec).resolve()
        self.results = []          # (section, ok, message)
        self.m = {}

    def ok(self, section, cond, msg):
        self.results.append((section, bool(cond), msg))
        return cond

    # ---------------------------------------------------------------- manifest
    def manifest(self):
        p = self.rec / "cvex.yml"
        if not self.ok("manifest", p.exists(), "cvex.yml present"):
            return
        m = self.m = yaml.safe_load(p.read_text()) or {}
        S = "manifest"
        self.ok(S, m.get("cvex_version") == 3, "cvex_version is 3")
        self.ok(S, m.get("cve") == self.rec.name, "cve matches the record directory")
        topo = m.get("topology")
        self.ok(S, topo in ("single", "target-attacker", "target+db-attacker"), f"topology is valid ({topo})")
        succ = m.get("success")
        self.ok(S, succ in ("flag", "verifier", "crash"), f"success criterion is valid ({succ})")
        chan = (m.get("capture") or {}).get("flag_channel")
        if succ == "flag":
            fl = m.get("flag") or {}
            self.ok(S, FLAG.match(str(fl.get("value", ""))), "flag.value has the form CVEX{32 hex}")
            self.ok(S, str(fl.get("plant", "")).startswith("file:"), "flag.plant names where the flag is planted")
            self.ok(S, chan in ("stdout", "network"), f"flag channel is stdout or network ({chan})")
        self.ok(S, (m.get("build") or {}).get("offline") is True, "build.offline: true")
        tgt = (m.get("services") or {}).get("target") or {}
        self.ok(S, DIGEST.search(str(tgt.get("image", ""))), "target image pinned by @sha256 digest")
        self.ok(S, tgt.get("trace"), "target trace expression set")
        self.ok(S, re.match(r"^(tcp:\d+|file:/\S+)$", str(tgt.get("ready", ""))), "target ready condition set")
        self.ok(S, DIGEST.search(str((m.get("recorder") or {}).get("image", ""))), "recorder image pinned by @sha256 digest")
        ph = m.get("phases") or {}
        self.ok(S, "benign" in ph and "attack" in ph, "benign and attack phases declared")
        if topo != "single":
            for name in ("benign", "attack"):
                c = ph.get(name) or {}
                self.ok(S, DIGEST.search(str(c.get("image", ""))), f"{name} client image pinned by @sha256 digest")
                self.ok(S, re.match(r"^10\.13\.0\.\d+$", str(c.get("ip", ""))), f"{name} client has a static IP")
        self.ok(S, int((m.get("limits") or {}).get("wall_clock_seconds", 0) or 0) > 0, "wall-clock limit set")

    # ---------------------------------------------------------------- build
    def build(self):
        S = "build"
        dfs = sorted(self.rec.glob("*/Dockerfile"))
        self.ok(S, dfs, "Dockerfiles present")
        for df in dfs:
            comp = df.parent.name
            text = df.read_text()
            stages = set()
            for line in logical_lines(text):
                mo = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
                if mo:
                    img = mo.group(1)
                    # a vendored `docker save` base (loaded offline before the build) counts
                    # as pinned: FROM cvex-base-<cve>:pinned backed by base-images/<comp>.image.tar
                    vb = self.rec / "base-images" / f"{comp}.image.tar"
                    vendored_base = img.startswith("cvex-base-") and vb.exists()
                    self.ok(S, img in stages or DIGEST.search(img) or vendored_base,
                            f"{comp}: base {img} pinned (digest or vendored image)")
                    if mo.group(2):
                        stages.add(mo.group(2))
                if line.lstrip().startswith("#"):
                    continue
                for rx, what in NET:
                    if re.search(rx, line):
                        self.ok(S, False, f"{comp}: no build-time network access ({what}: {line.strip()[:80]})")
            if (df.parent / "vendor").exists():
                self.ok(S, "sha256sum -c" in text, f"{comp}: Dockerfile verifies vendored checksums")
        # every vendored file is listed in a SHA256SUMS that matches (or a hash lock)
        for vend in sorted(self.rec.glob("*/vendor")):
            for d in sorted([vend, *[p for p in vend.rglob("*") if p.is_dir()]]):
                direct = [p for p in d.iterdir() if p.is_file()
                          and p.name not in ("SHA256SUMS", "debs.lock", "requirements.lock", "package-lock.json")]
                if not direct or "npm-cache" in d.parts:
                    continue   # npm's cache is content-addressed and checked against package-lock.json
                sums = d / "SHA256SUMS"
                lock = d / "requirements.lock"
                rel = d.relative_to(self.rec)
                if sums.exists():
                    listed = dict(reversed(l.split(None, 1)) for l in sums.read_text().splitlines() if l.strip())
                    listed = {k.strip(): v for k, v in listed.items()}
                    bad = [p.name for p in direct if listed.get(p.name) != sha256(p)]
                    self.ok(S, not bad, f"{rel}: SHA256SUMS covers and matches every file"
                            + (f" (mismatch: {', '.join(bad[:3])})" if bad else ""))
                elif lock.exists():
                    hashes = set(re.findall(r"--hash=sha256:([0-9a-f]{64})", lock.read_text()))
                    bad = [p.name for p in direct if p.suffix == ".whl" and sha256(p) not in hashes]
                    self.ok(S, not bad, f"{rel}: requirements.lock pins every wheel by hash")
                else:
                    self.ok(S, False, f"{rel}: vendored files have a SHA256SUMS")
        # vendored base images (docker save tars loaded offline before the build)
        bdir = self.rec / "base-images"
        if bdir.exists():
            tars = [p for p in bdir.iterdir() if p.suffix == ".tar"]
            sums = bdir / "SHA256SUMS"
            if sums.exists():
                listed = {k.strip(): v for v, k in
                          (l.split(None, 1) for l in sums.read_text().splitlines() if l.strip())}
                bad = [p.name for p in tars if listed.get(p.name) != sha256(p)]
                self.ok(S, tars and not bad, "base-images/: SHA256SUMS covers and matches every image tar"
                        + (f" (mismatch: {', '.join(bad[:3])})" if bad else ""))
            else:
                self.ok(S, False, "base-images/: image tars have a SHA256SUMS")

    # ---------------------------------------------------------------- content
    def content(self):
        S = "content"
        topo = self.m.get("topology")
        todo = [str(p.relative_to(self.rec)) for p in files(self.rec)
                if p.suffix not in (".deb", ".gz", ".tgz", ".whl", ".tar", ".zip", ".jar")
                and "base-images" not in p.relative_to(self.rec).parts
                and p.name not in ("STATUS.md", "TODO.md")
                and re.search(r"\b(TODO|FIXME|XXX)\b", p.read_text(errors="replace"))]
        self.ok(S, not todo, "no TODO markers" + (f" ({', '.join(todo[:4])})" if todo else ""))
        self.ok(S, not (self.rec / "TODO.md").exists(), "no TODO.md")
        if topo == "single":
            b, a = self.rec / "target" / "benign.sh", self.rec / "target" / "attack.sh"
            self.ok(S, not (self.rec / "benign").exists() and not (self.rec / "attacker").exists(),
                    "no unused client components (single topology)")
        else:
            b, a = self.rec / "benign" / "interact.sh", self.rec / "attacker" / "exploit.sh"
        self.ok(S, a.exists(), f"attack workload {a.relative_to(self.rec)} present")
        if self.ok(S, b.exists(), f"benign workload {b.relative_to(self.rec)} present"):
            body = [l for l in b.read_text().splitlines() if l.strip() and not l.lstrip().startswith(("#", "//"))]
            placeholder = len(body) < 1 or any(re.search(r"benign:|import \w+; print", l) for l in body) and len(body) <= 2
            self.ok(S, not placeholder, "benign workload is not a placeholder")
        if self.m.get("success") == "flag":
            self.ok(S, (self.rec / "target" / "plant-flag.sh").exists(), "target/plant-flag.sh present")
        self.ok(S, (self.rec / "recorder" / "capture.sh").exists(), "recorder/capture.sh present")
        self.ok(S, (self.rec / "compose.yml").exists(), "compose.yml present")

    # ---------------------------------------------------------------- dataset
    def dataset(self):
        S = "dataset"
        ds = self.rec / "dataset"
        self.ok(S, (self.rec / ".cvex-lock").exists(), "record locked (.cvex-lock)")
        vp = ds / "verdict.json"
        if not self.ok(S, vp.exists(), "dataset/verdict.json present"):
            return
        v = json.loads(vp.read_text())
        self.ok(S, v.get("success") is True, "verdict: success")
        self.ok(S, v.get("criterion") == self.m.get("success"), "verdict criterion matches cvex.yml")
        if self.m.get("success") == "flag":
            flag = (self.m.get("flag") or {}).get("value")
            self.ok(S, v.get("flag_observed") == flag == v.get("flag_planted"), "observed flag == planted flag")
            self.ok(S, v.get("benign_clean") is True, "benign phase never saw the flag")
            if (self.m.get("capture") or {}).get("flag_channel") == "network":
                ap = ds / "attack" / "attack.pcap"
                self.ok(S, ap.exists() and flag.encode() in ap.read_bytes(), "flag travels in the attack pcap")
        pins = {"target": (self.m.get("services") or {}).get("target", {}).get("image", ""),
                "recorder": (self.m.get("recorder") or {}).get("image", "")}
        if self.m.get("topology") != "single":
            pins["benign"] = (self.m.get("phases") or {}).get("benign", {}).get("image", "")
            pins["attacker"] = (self.m.get("phases") or {}).get("attack", {}).get("image", "")
        imgs = v.get("images") or {}
        for comp, ref in pins.items():
            self.ok(S, "@sha256:" in str(ref) and imgs.get(comp) == "sha256:" + str(ref).split("@sha256:")[1],
                    f"{comp} image of the reference run matches its pin")
        self.ok(S, v.get("image_pins_match") is True, "verdict: image_pins_match")
        for ph in ("benign", "attack"):
            pc, sc = ds / ph / f"{ph}.pcap", ds / ph / f"{ph}.syscalls.log"
            self.ok(S, pc.exists(), f"{ph} pcap present")
            self.ok(S, sc.exists() and sc.stat().st_size > 0, f"{ph} syscall trace present and non-empty")
        mf = ds / "MANIFEST.sha256"
        if self.ok(S, mf.exists(), "MANIFEST.sha256 present"):
            listed = {}
            for l in mf.read_text().splitlines():
                if l.strip():
                    h, name = l.split(None, 1)
                    listed[name.strip()] = h
            actual = {str(p.relative_to(ds)): sha256(p) for p in ds.rglob("*")
                      if p.is_file() and p.name != "MANIFEST.sha256"}
            self.ok(S, listed == actual, "MANIFEST.sha256 covers and matches every dataset file")

    def run(self):
        self.manifest()
        self.build()
        self.content()
        self.dataset()
        return all(ok for _, ok, _ in self.results)

    # ---------------------------------------------------------------- STATUS.md
    def status_md(self, conformant):
        m, rec = self.m, self.rec
        df = (rec / "target" / "Dockerfile").read_text()
        about = []
        for l in df.splitlines():
            if not l.startswith("#"):
                break
            if "Offline build" in l or "sources and OS packages" in l or "Python wheels" in l:
                continue
            about.append(l.lstrip("# ").rstrip())
        bases = sorted({mo.group(1) for d in rec.glob("*/Dockerfile")
                        for mo in re.finditer(r"^FROM\s+(?:--platform=\S+\s+)?(\S+@sha256:\S+)", d.read_text(), re.M)})
        locks = sorted(str(p.relative_to(rec)) for p in rec.glob("*/vendor/**/*")
                       if p.name in ("SHA256SUMS", "debs.lock", "requirements.lock", "package-lock.json"))
        v = json.loads((rec / "dataset" / "verdict.json").read_text()) if (rec / "dataset" / "verdict.json").exists() else {}
        ds = rec / "dataset"
        size = lambda p: f"{p.stat().st_size / 1024:.1f} KiB" if p.exists() else "missing"
        fails = [msg for _, ok, msg in self.results if not ok]
        flag = (m.get("flag") or {})
        out = [f"# {rec.name}", "",
               ("**CONFORMANT.** This record passes every check of `tools/cvex_check.py`."
                if conformant else f"**NOT CONFORMANT** ({len(fails)} failing checks, listed below)."), "",
               " ".join(about), "",
               "## Record", "",
               f"- Topology: `{m.get('topology')}`; success criterion: `{m.get('success')}`"
               + (f"; flag planted at `{flag.get('plant')}`, captured on the `{(m.get('capture') or {}).get('flag_channel')}` channel"
                  if m.get("success") == "flag" else ""),
               f"- Traced process: `{(m.get('services') or {}).get('target', {}).get('trace')}`; "
               f"ready when `{(m.get('services') or {}).get('target', {}).get('ready')}`",
               "- Builds offline (`docker build --network=none`) from digest-pinned base images:",
               *[f"  - `{b}`" for b in bases],
               "- Vendored inputs, each checked at build time:",
               *[f"  - `{l}`" for l in locks],
               "", "## Reference dataset (`dataset/`)", "",
               f"- benign: `benign.pcap` ({size(ds / 'benign' / 'benign.pcap')}), "
               f"`benign.syscalls.log` ({size(ds / 'benign' / 'benign.syscalls.log')})",
               f"- attack: `attack.pcap` ({size(ds / 'attack' / 'attack.pcap')}), "
               f"`attack.syscalls.log` ({size(ds / 'attack' / 'attack.syscalls.log')})",
               f"- verdict: success `{v.get('success')}`, observed `{v.get('flag_observed')}`, "
               f"benign clean `{v.get('benign_clean')}`, image pins match `{v.get('image_pins_match')}`",
               "- images of the reference run (pinned in `cvex.yml`):",
               *[f"  - {c}: `{i}`" for c, i in (v.get("images") or {}).items()],
               "", "## Reproduce", "", "```sh",
               f"python3 tools/cvex_run.py CVEX-records/{rec.name}   # build offline, run both phases, verify",
               f"python3 tools/cvex_check.py CVEX-records/{rec.name} # conformance check",
               "```", "",
               "A rebuild produces new image ids (layer timestamps differ), so `image_pins_match`",
               "is true only for the reference images; the inputs that determine their content are",
               "all pinned or vendored. Use `--pin` to record the ids of a new reference build.", ""]
        if fails:
            out += ["## Failing checks", ""] + [f"- {f}" for f in fails] + [""]
        (rec / "STATUS.md").write_text("\n".join(out))


def main():
    args = sys.argv[1:]
    status = "--status" in args
    recs = [a for a in args if a != "--status"]
    if not recs:
        print(__doc__)
        sys.exit(2)
    all_ok = True
    for r in recs:
        c = Check(r)
        ok = c.run()
        all_ok &= ok
        print(f"{'PASS' if ok else 'FAIL'}  {c.rec.name}  "
              f"({sum(o for _, o, _ in c.results)}/{len(c.results)} checks)")
        for sec, o, msg in c.results:
            if not o:
                print(f"      [{sec}] {msg}")
        if status:
            c.status_md(ok)
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
