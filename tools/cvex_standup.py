#!/usr/bin/env python3
"""cvex_standup.py <record> [--keep] -- install & stand up a vulnerable service.

For records where only the benign + flag halves exist (no exploit), this is the
conformance check: it builds the target (and any auxiliary/db service), brings it
up, confirms the service becomes reachable and the flag is planted, then runs the
benign interaction under capture. It writes dataset/benign/ and standup.json.
It never runs an attacker and never needs one.

Exit 0 iff the service stood up (ready) AND the flag is present.
"""
import json, re, subprocess, sys, time
from pathlib import Path
import yaml



def dsh(*a, check=False, timeout=None):
    return subprocess.run(["docker", *a], capture_output=True, text=True, check=check, timeout=timeout)


class Standup:
    def __init__(self, rec, keep=False):
        self.rec = Path(rec).resolve()
        self.cve = self.rec.name
        self.keep = keep
        self.m = yaml.safe_load((self.rec / "cvex.yml").read_text())
        self.ns = f"cvex-{self.cve.lower()}"
        import hashlib
        h = int(hashlib.md5(self.cve.encode()).hexdigest(), 16)
        b2, b3 = (h % 240) + 1, ((h >> 8) % 240) + 1   # unique /24 per record
        self.NET = f"cvexnet-{self.cve.lower()}"
        self.subnet = f"10.{b2}.{b3}.0/24"
        self.IP = {"target": f"10.{b2}.{b3}.10", "db": f"10.{b2}.{b3}.11", "benign": f"10.{b2}.{b3}.30"}
        ready = str(self.m["services"]["target"].get("ready", "") or "")
        self.topo = self.m.get("topology", "target-attacker")
        self.single = self.topo == "single"
        self.ready_file = ready.split(":", 1)[1] if ready.startswith("file:") else "/ready"
        self.port = int(ready.split(":")[1]) if ready.startswith("tcp:") else 80
        self.has_db = "db" in self.m.get("services", {})
        self.target_env = self.m["services"]["target"].get("environment") or []
        dbsvc = self.m.get("services", {}).get("db", {}) or {}
        self.db_alias = dbsvc.get("alias") or "db"
        self.db_env = dbsvc.get("environment") or []
        self.out = self.rec / "_out"
        self.names = []

    def build(self, comp):
        d = self.rec / comp
        if not (d / "Dockerfile").exists():
            return False
        img = f"{self.ns}-{comp}"
        # vulhub bases need the network to pull; app layer is tiny
        r = dsh("build", "-t", img, "--network=default", str(d), timeout=3600)
        if r.returncode:
            # retry without --network flag (older docker)
            r = dsh("build", "-t", img, str(d), timeout=3600)
        if r.returncode:
            raise RuntimeError(f"build {comp} failed:\n{r.stdout[-1500:]}\n{r.stderr[-1500:]}")
        return True

    def net_up(self):
        dsh("network", "rm", self.NET)
        dsh("network", "create", "--subnet", self.subnet, self.NET, check=True)

    def run_detached(self, comp, extra):
        name = f"{self.ns}-{comp}"
        dsh("rm", "-f", name)
        dsh("run", "-d", "--name", name, *extra, name, check=True)
        self.names.append(name)
        return name

    def wait_ready(self, tgt):
        deadline = time.time() + 300
        while time.time() < deadline:
            st = dsh("inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", tgt).stdout.strip()
            if st.startswith("false") and not st.endswith(" 0"):
                return False  # crashed on boot
            # tcp probe from a throwaway container on the net
            p = dsh("run", "--rm", "--network", self.NET, "busybox:1.36", "sh", "-c",
                    f"nc -z target {self.port}", timeout=30)
            if p.returncode == 0:
                return True
            time.sleep(2)
        return False

    def teardown(self):
        for n in self.names:
            dsh("rm", "-f", n)
        dsh("network", "rm", self.NET)

    def wait_ready_file(self, tgt):
        deadline = time.time() + 300
        while time.time() < deadline:
            st = dsh("inspect", "-f", "{{.State.Running}} {{.State.ExitCode}}", tgt).stdout.strip()
            if st.startswith("false") and not st.endswith(" 0"):
                return False
            if dsh("exec", tgt, "test", "-f", self.ready_file).returncode == 0:
                return True
            time.sleep(2)
        return False

    def run_single(self):
        verdict = {"cve": self.cve, "source": self.m.get("source", "?"), "topology": "single",
                   "service_up": False, "flag_present": False, "benign_ran": False}
        self.build("target")
        self.net_up()
        try:
            tgt = self.run_detached("target", ["--network", self.NET, "--ip", self.IP["target"],
                                               "--network-alias", "target", "--cap-add", "SYS_PTRACE"])
            verdict["service_up"] = self.wait_ready_file(tgt)
            fr = dsh("exec", tgt, "sh", "-c", "cat /flag 2>/dev/null")
            verdict["flag_present"] = self.m["flag"]["value"] in fr.stdout
            if verdict["service_up"]:
                b = dsh("exec", tgt, "sh", "/benign.sh", timeout=180)
                verdict["benign_ran"] = b.returncode == 0
                verdict["benign_stdout"] = (b.stdout or b.stderr or "")[-400:]
        finally:
            if not self.keep:
                self.teardown()
        (self.rec / "standup.json").write_text(json.dumps(verdict, indent=2))
        print(json.dumps(verdict, indent=2))
        return verdict

    def run(self):
        if self.single:
            return self.run_single()
        verdict = {"cve": self.cve, "source": self.m.get("source", "?"),
                   "service_up": False, "flag_present": False, "benign_ran": False}
        self.build("target")
        if self.has_db:
            self.build("db")
        self.build("benign")
        self.build("recorder")
        self.net_up()
        if self.out.exists():
            import shutil; shutil.rmtree(self.out)
        self.out.mkdir()
        try:
            if self.has_db:
                dbx = ["--network", self.NET, "--ip", self.IP["db"], "--network-alias", "db",
                       "--network-alias", self.db_alias]
                for e in self.db_env:
                    dbx += ["-e", e]
                self.run_detached("db", dbx)
                time.sleep(15)   # let the database initialize before the app connects
            tgtx = ["--network", self.NET, "--ip", self.IP["target"],
                    "--network-alias", "target", "--cap-add", "SYS_PTRACE"]
            for e in self.target_env:
                tgtx += ["-e", e]
            tgt = self.run_detached("target", tgtx)
            verdict["service_up"] = self.wait_ready(tgt)
            fr = dsh("exec", tgt, "sh", "-c", "cat /flag 2>/dev/null")
            verdict["flag_present"] = self.m["flag"]["value"] in fr.stdout
            if verdict["service_up"]:
                # recorder sidecar + benign client with capture
                rname = f"{self.ns}-recorder"
                dsh("rm", "-f", rname)
                dsh("run", "-d", "--name", rname, "--network", f"container:{tgt}",
                    "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                    "-e", "PHASE=benign", "-e", "OUTDIR=/out", "-e", "TRACE=",
                    "-v", f"{self.out}:/out", f"{self.ns}-recorder")
                self.names.append(rname)
                time.sleep(3)
                b = dsh("run", "--rm", "--network", self.NET, "--ip", self.IP["benign"],
                        "-e", "TARGET=target", "-e", f"PORT={self.port}", f"{self.ns}-benign", timeout=180)
                verdict["benign_ran"] = b.returncode == 0
                verdict["benign_stdout"] = (b.stdout or "")[-400:]
                dsh("kill", "-s", "INT", rname); time.sleep(2)
                ds = self.rec / "dataset" / "benign"
                ds.mkdir(parents=True, exist_ok=True)
                for suf in (".pcap", ".syscalls.log"):
                    src = self.out / f"benign{suf}"
                    if src.exists():
                        import shutil; shutil.copy(src, ds / f"benign{suf}")
        finally:
            if not self.keep:
                self.teardown()
        (self.rec / "standup.json").write_text(json.dumps(verdict, indent=2))
        print(json.dumps(verdict, indent=2))
        return verdict


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]  # topology auto-detected
    keep = "--keep" in sys.argv
    v = Standup(args[0], keep).run()
    ok = v["service_up"] and v["flag_present"]
    print("STANDUP_OK" if ok else "STANDUP_FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
