#!/usr/bin/env python3
"""
cvex_run.py -- execute a CVEX v3 record and produce a real dataset.

For each of the two phases (benign, attack) it:
  1. builds + starts the target (+db) on a fixed-IP network;
  2. starts the recorder sidecar (shares the target net+PID ns) which runs
     tcpdump (-> <phase>.pcap) and strace on the traced process
     (-> <phase>.syscalls.log);
  3. runs the phase's client (benign/attacker), capturing its stdout;
  4. stops the recorder (flushing captures) and tears everything down.

Then it verifies the flag (captured flag == planted flag, or a crash witness)
and writes dataset/ (benign+attack pcap+syscalls, flag.observed, verdict.json,
MANIFEST.sha256). Writing dataset/ "locks" the record so the generator will not
regenerate over it.

Conformance features (CVEX_v3_DESIGN.md sections 4, 6, 7):
  - `build: {offline: true}` in cvex.yml builds every image with --network=none;
  - `services.target.ready` (tcp:N | file:/path) is waited for before each phase;
  - `limits.wall_clock_seconds` bounds each phase's client/script;
  - the attacker never receives the flag; a flag seen in the benign phase fails
    the run (verdict `benign_clean`);
  - built image ids are recorded in verdict.json and compared with the
    `@sha256:` pins in cvex.yml (verdict `image_pins_match`).

Requires: docker, docker compose, python3, PyYAML.
Usage: python3 tools/cvex_run.py CVEX-records/CVE-2021-41773 [--settle 3] [--pin]
"""
import argparse, hashlib, json, re, shutil, socket, subprocess, sys, time
from pathlib import Path
import yaml

def sh(*a, **k):
    return subprocess.run(a, capture_output=True, text=True, **k)

def dsh(*a, check=False, **k):
    r = sh("docker", *a, **k)
    if check and r.returncode != 0:
        raise RuntimeError(f"docker {' '.join(a)} failed:\n{r.stderr}")
    return r

NET = "cvexnet"
SUBNET = "10.13.0.0/24"
IP = {"target": "10.13.0.10", "db": "10.13.0.11",
      "attacker": "10.13.0.20", "benign": "10.13.0.30"}

class Runner:
    def __init__(self, rec, settle, pin=False):
        self.rec = Path(rec).resolve()
        self.cve = self.rec.name
        self.settle = settle
        self.pin = pin
        self.m = yaml.safe_load((self.rec / "cvex.yml").read_text())
        self.flag = (self.m.get("flag") or {}).get("value", "")  # absent for verifier/crash modes
        self.success = self.m.get("success", "flag")
        self.channel = self.m.get("capture", {}).get("flag_channel", "stdout")
        self.topo = self.m.get("topology", "target-attacker")
        self.trace = str(self.m["services"]["target"].get("trace", "") or "")
        self.port = self._port()
        # extra capabilities a record's target genuinely needs (e.g. SYS_ADMIN to mount)
        self.caps = [a for c in (self.m["services"]["target"].get("cap_add") or [])
                     for a in ("--cap-add", str(c))]
        self.caps += [a for o in (self.m["services"]["target"].get("security_opt") or [])
                      for a in ("--security-opt", str(o))]
        self.offline = bool((self.m.get("build") or {}).get("offline"))
        self.ready = str(self.m["services"]["target"].get("ready", "") or "")
        self.db_warmup = int((self.m.get("limits") or {}).get("db_warmup_seconds", 30) or 30)
        self.limit = int((self.m.get("limits") or {}).get("wall_clock_seconds", 0) or 0) or None
        self.image_ids = {}
        self.ns = f"cvex-{self.cve.lower()}"
        self.out = self.rec / "_out"
        self.names = []

    def _port(self):
        r = self.m["services"]["target"].get("ready", "")
        mo = re.match(r"tcp:(\d+)", str(r))
        if mo: return int(mo.group(1))
        for ph in ("attack", "benign"):
            pass
        return 80

    # ---- image builds ----
    def build(self):
        # single topology: the phases run inside the target, there are no client images
        clients = () if self.topo == "single" else ("benign", "attacker")
        for comp in ("target", *clients, "recorder",
                     "db" if self.topo == "target+db-attacker" else None):
            if comp and (self.rec / comp / "Dockerfile").exists():
                tag = f"{self.ns}-{comp}"
                # offline base: a vendored `docker save` tar loaded before the build, so
                # `FROM cvex-base-<cve>:pinned` resolves locally without any registry.
                base_tar = self.rec / "base-images" / f"{comp}.image.tar"
                if base_tar.exists():
                    sums = base_tar.parent / "SHA256SUMS"
                    if sums.exists():
                        c = subprocess.run(["sha256sum", "-c", "--quiet", "--ignore-missing", "SHA256SUMS"],
                                           cwd=str(base_tar.parent), capture_output=True, text=True)
                        if c.returncode != 0:
                            raise RuntimeError(f"vendored base image checksum failed for {comp}:\n{c.stdout}{c.stderr}")
                    print(f"  load vendored base for {comp} <- {base_tar.name}")
                    dsh("load", "-i", str(base_tar), check=True)
                print(f"  build {comp} -> {tag}" + (" (offline)" if self.offline else ""))
                net = ["--network=none"] if self.offline else []
                r = dsh("build", *net, "-t", tag, str(self.rec / comp))
                if r.returncode != 0:
                    raise RuntimeError(f"build {comp} failed:\n{r.stderr[-2000:]}")
                self.image_ids[comp] = dsh("image", "inspect", "-f", "{{.Id}}", tag).stdout.strip()

    def write_pins(self):
        """Point the existing @sha256 pins of cvex.yml at the images just built."""
        p = self.rec / "cvex.yml"
        text = p.read_text()
        for comp, iid in self.image_ids.items():
            text = re.sub(rf"(cvex/{re.escape(self.cve.lower())}-{comp})@sha256:\S+",
                          rf"\1@{iid}", text)
        tmp = p.with_suffix(".yml.tmp")
        tmp.write_text(text)
        tmp.replace(p)
        self.m = yaml.safe_load(text)

    def pinned_ids(self):
        """{component: sha256:...} for the images cvex.yml pins by digest."""
        pins = {}
        img = str(self.m["services"]["target"].get("image", ""))
        if "@sha256:" in img:
            pins["target"] = "sha256:" + img.split("@sha256:")[1]
        for ph, comp in (("benign", "benign"), ("attack", "attacker")):
            img = str(((self.m.get("phases") or {}).get(ph) or {}).get("image", "") or "")
            if "@sha256:" in img:
                pins[comp] = "sha256:" + img.split("@sha256:")[1]
        img = str((self.m.get("recorder") or {}).get("image", "") or "")
        if "@sha256:" in img:
            pins["recorder"] = "sha256:" + img.split("@sha256:")[1]
        return pins

    def wait_ready(self, tgt):
        """Block until the target's declared ready condition holds."""
        if not self.ready:
            return
        deadline = time.time() + (self.limit or 600)
        kind, _, arg = self.ready.partition(":")
        while time.time() < deadline:
            if kind == "tcp":
                try:
                    with socket.create_connection((IP["target"], int(arg)), timeout=2):
                        return
                except OSError:
                    pass
            elif kind == "file":
                if dsh("exec", tgt, "test", "-e", arg).returncode == 0:
                    return
            else:
                raise RuntimeError(f"unknown ready condition {self.ready!r}")
            if dsh("inspect", "-f", "{{.State.Running}}", tgt).stdout.strip() != "true":
                raise RuntimeError("target exited before becoming ready")
            time.sleep(1)
        raise RuntimeError(f"target not ready ({self.ready}) within {self.limit or 600}s")

    # ---- low-level helpers ----
    def net_up(self):
        dsh("network", "rm", NET)
        dsh("network", "create", "--subnet", SUBNET, NET, check=True)

    def net_down(self):
        dsh("network", "rm", NET)

    def run_detached(self, comp, extra):
        name = f"{self.ns}-{comp}"
        dsh("rm", "-f", name)
        args = ["run", "-d", "--name", name] + extra + [f"{self.ns}-{comp}"]
        dsh(*args, check=True)
        self.names.append(name)
        return name

    def stop_all(self):
        for n in reversed(self.names):
            dsh("rm", "-f", n)
        self.names = []

    def phase_single(self, which):
        """single topology: local exploit. Run /benign.sh or /attack.sh inside the
        target under strace (syscalls); tcpdump sidecar captures any loopback pcap."""
        print(f"  [{which}] (single) starting target")
        self.net_up()
        self.out.mkdir(exist_ok=True)
        tgt = self.run_detached("target",
              ["--network", NET, "--ip", IP["target"], "--network-alias", "target",
               "--cap-add", "SYS_PTRACE", *self.caps, "-e", f"CVEX_FLAG={self.flag}",
               "-v", f"{self.out}:/out"])
        self.wait_ready(tgt)
        rname = f"{self.ns}-recorder"
        dsh("rm", "-f", rname)
        dsh("run", "-d", "--name", rname,
            "--network", f"container:{tgt}", "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
            "-e", f"PHASE={which}", "-e", "OUTDIR=/out", "-e", "TRACE=",
            "-v", f"{self.out}:/out", f"{self.ns}-recorder", check=True)
        self.names.append(rname)
        time.sleep(max(self.settle, 2))
        script = "/benign.sh" if which == "benign" else "/attack.sh"
        print(f"  [{which}] exec {script} under strace")
        # capture the script's own exit code so crash-class records can detect a crash
        # strace -f waits for every descendant: a server the script orphaned (e.g. the
        # binary `go run` spawns) would hang the phase forever. So once the script itself
        # has exited, give it a moment, then SIGTERM strace (detaches + flushes the log).
        rcf = f"/tmp/.cvex_rc_{which}"
        r = dsh("exec", tgt, "timeout", str(self.limit or 3600), "sh", "-c",
                f"rm -f {rcf}; strace -f -I2 -qq -tt -o /out/{which}.syscalls.log "
                f"sh -c '{script}; echo $? > {rcf}' & sp=$!; "
                f"while [ ! -e {rcf} ] && kill -0 $sp 2>/dev/null; do sleep 0.5; done; "
                f"for i in 1 2 3 4 5 6; do kill -0 $sp 2>/dev/null || break; sleep 0.5; done; "
                f"kill $sp 2>/dev/null; wait $sp; echo CVEX_RC=$(cat {rcf} 2>/dev/null || echo 1)")
        stdout = r.stdout + r.stderr
        mo = re.search(r"CVEX_RC=(\d+)", stdout)
        rc = int(mo.group(1)) if mo else r.returncode
        crashed = rc is not None and rc >= 128   # 128+signal => terminated by signal
        dsh("kill", "-s", "INT", rname); time.sleep(2)
        self.stop_all(); self.net_down()
        return stdout, crashed

    def phase(self, which):
        """Run one phase; return client stdout."""
        if self.topo == "single":
            return self.phase_single(which)
        print(f"  [{which}] starting target + recorder")
        self.net_up()
        (self.out).mkdir(exist_ok=True)
        # db first (a DB-backed target may fail/stall if its database isn't up yet;
        # a db image that imports a dump needs time before it accepts connections)
        if self.topo == "target+db-attacker":
            dbsvc = self.m.get("services", {}).get("db", {}) or {}
            db_alias = dbsvc.get("alias") or "db"
            dbx = ["--network", NET, "--ip", IP["db"], "--network-alias", "db",
                   "--network-alias", db_alias, "-e", f"CVEX_FLAG={self.flag}"]
            for e in (dbsvc.get("environment") or []):
                dbx += ["-e", str(e)]
            self.run_detached("db", dbx)
            time.sleep(self.db_warmup)
        # target
        tgt = self.run_detached("target",
              ["--network", NET, "--ip", IP["target"], "--network-alias", "target",
               *self.caps, "-e", f"CVEX_FLAG={self.flag}",
               *sum((["-e", str(e)] for e in (self.m["services"]["target"].get("environment") or [])), [])])
        self.wait_ready(tgt)
        # recorder shares target net + pid ns
        rname = f"{self.ns}-recorder"
        dsh("rm", "-f", rname)
        dsh("run", "-d", "--name", rname,
            "--network", f"container:{tgt}", "--pid", f"container:{tgt}",
            "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--cap-add", "SYS_PTRACE",
            "-e", f"PHASE={which}", "-e", "OUTDIR=/out", "-e", f"TRACE={self.trace}",
            "-v", f"{self.out}:/out", f"{self.ns}-recorder", check=True)
        self.names.append(rname)
        # wait until the recorder has actually started tcpdump+strace (it writes a marker)
        marker = self.out / f".{which}.ready"
        for _ in range(60):
            if marker.exists():
                break
            time.sleep(0.5)
        time.sleep(max(self.settle, 2))  # extra settle so capture is live before traffic

        # client
        client = "benign" if which == "benign" else "attacker"
        print(f"  [{which}] running {client}")
        cname = f"{self.ns}-{client}"
        dsh("rm", "-f", cname)
        # the attacker must obtain the flag by exploitation: it is never given the flag
        env = ["-e", "TARGET=target", "-e", f"PORT={self.port}"]
        try:
            r = dsh("run", "--name", cname, "--network", NET, "--ip", IP[client],
                    *env, f"{self.ns}-{client}", timeout=self.limit)
        except subprocess.TimeoutExpired as e:
            dsh("rm", "-f", cname)
            r = subprocess.CompletedProcess(e.cmd, 124, (e.stdout or b"").decode(errors="replace")
                                            if isinstance(e.stdout, bytes) else (e.stdout or ""),
                                            f"\nphase timed out after {self.limit}s\n")
        self.names.append(cname)
        stdout = r.stdout + r.stderr
        # crash witness: did the target die during this phase?
        st = dsh("inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", tgt).stdout.strip()
        crashed = st.startswith("false") and not st.endswith(" 0")
        # stop recorder cleanly so tcpdump/strace flush
        dsh("kill", "-s", "INT", rname)
        time.sleep(2)
        self.stop_all()
        self.net_down()
        return stdout, crashed

    # ---- verification ----
    def observed_flag(self, stdout, pcap):
        mo = re.search(r"CVEX_FLAG=(\S+)", stdout)
        if mo:
            return mo.group(1)
        if pcap.exists():
            data = pcap.read_bytes()
            if self.flag.encode() in data:
                return self.flag
        return None

    def run(self):
        if self.out.exists():
            shutil.rmtree(self.out)
        self.out.mkdir()
        self.build()
        if self.pin:
            self.write_pins()
        b_out, _ = self.phase("benign")
        a_out, crashed = self.phase("attack")

        ds = self.rec / "dataset"
        if ds.exists():
            shutil.rmtree(ds)
        (ds / "benign").mkdir(parents=True)
        (ds / "attack").mkdir(parents=True)
        for ph in ("benign", "attack"):
            for suf, dst in ((".pcap", f"{ph}.pcap"), (".syscalls.log", f"{ph}.syscalls.log")):
                src = self.out / f"{ph}{suf}"
                if src.exists():
                    # syscall traces can be huge for slow-booting JVM apps; gzip them so the
                    # committed dataset stays lean (cvex_check accepts .log or .log.gz).
                    if suf == ".syscalls.log" and src.stat().st_size > 20 * 2**20:
                        import gzip as _gz
                        with open(src, "rb") as fi, _gz.open(str(ds / ph / dst) + ".gz", "wb", compresslevel=6) as fo:
                            shutil.copyfileobj(fi, fo)
                    else:
                        shutil.copy(src, ds / ph / dst)

        arc = None
        mo = re.search(r"CVEX_RC=(\d+)", a_out)
        if mo:
            arc = int(mo.group(1))
        if self.success == "crash":
            ok = crashed
            observed = "CRASH" if crashed else None
        elif self.success == "verifier":
            # CVE-Genie's own verifier.py is the oracle: exit 0 == reproduced
            ok = (arc == 0)
            # the flag the verifier printed (last non-empty line before the RC marker)
            lines = [l for l in a_out.splitlines() if l.strip() and "CVEX_RC=" not in l]
            observed = (lines[-1].strip() if lines else "VERIFIED") if ok else None
        else:
            observed = self.observed_flag(a_out, ds / "attack" / "attack.pcap")
            ok = observed == self.flag
        # the benign phase must never see the flag
        benign_clean = True
        if self.flag and self.success == "flag":
            bp = ds / "benign" / "benign.pcap"
            benign_clean = (self.flag not in b_out and
                            not (bp.exists() and self.flag.encode() in bp.read_bytes()))
            ok = ok and benign_clean
        pins = self.pinned_ids()
        pins_match = (all(self.image_ids.get(c) == d for c, d in pins.items()) if pins else None)
        (ds / "flag.observed").write_text((observed or "") + "\n")

        verdict = {"cve": self.cve, "success": bool(ok), "criterion": self.success,
                   "channel": self.channel, "flag_planted": self.flag,
                   "flag_observed": observed,
                   "benign_clean": benign_clean,
                   "images": self.image_ids,
                   "image_pins_match": pins_match,
                   "benign": {"pcap": (ds/"benign"/"benign.pcap").exists(),
                              "syscalls": (ds/"benign"/"benign.syscalls.log").exists()},
                   "attack": {"pcap": (ds/"attack"/"attack.pcap").exists(),
                              "syscalls": (ds/"attack"/"attack.syscalls.log").exists()}}
        (ds / "verdict.json").write_text(json.dumps(verdict, indent=2) + "\n")
        # manifest
        lines = []
        for p in sorted(ds.rglob("*")):
            if p.is_file() and p.name != "MANIFEST.sha256":
                lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ds)}")
        (ds / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")
        if ok:
            (self.rec / ".cvex-lock").write_text("locked: has a verified dataset; do not regenerate\n")
            (self.rec / "TODO.md").unlink(missing_ok=True)   # see tools/gen_todo.py
        else:
            # failed run: keep the dataset for debugging but stay regenerable
            (self.rec / ".cvex-lock").unlink(missing_ok=True)
            print("---- attack output (tail) ----")
            print("\n".join(a_out.splitlines()[-40:]))
        shutil.rmtree(self.out, ignore_errors=True)
        return verdict

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("record")
    ap.add_argument("--settle", type=int, default=3)
    ap.add_argument("--pin", action="store_true",
                    help="write the ids of the images built now into cvex.yml's @sha256 pins")
    a = ap.parse_args()
    v = Runner(a.record, a.settle, a.pin).run()
    print(json.dumps(v, indent=2))
    print("SUCCESS" if v["success"] else "FAILED")
    sys.exit(0 if v["success"] else 1)

if __name__ == "__main__":
    main()
