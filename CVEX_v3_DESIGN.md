# CVEX v3: A Docker-Only, Flag-Based Format for Reproducible CVEs

**Status:** design proposal
**Supersedes:** the Vagrant/Ansible framework in `CVEX/` (generation 3)
**Date:** 2026-10

This document defines a new CVEX record format. It has three non-negotiable
properties:

1. **Docker-only.** A record is a Docker Compose project. No VMs, no hypervisor,
   no per-host provisioning.
2. **Paired benign/attack capture.** Every record is exercised twice — once with
   legitimate traffic, once with the exploit — and both runs are captured
   (network packets *and* system calls). The result is a labeled dataset:
   benign vs. attack, over the same service.
3. **Flag-based success.** Every record plants a secret **flag** that is
   reachable *only* by successfully exploiting the vulnerability. The attack
   succeeds if and only if it captures the flag. This is the single,
   uniform definition of "the exploit worked."

The format descends from all three previous generations (see
`README_Historic.md`): the `collector`/sidecar capture and `exploit_verification`
of generation 1, the Docker `server`/`client`/`listener` pattern of generation 2,
and the `cvex.yml` manifest, HTTPS interception, and process tracing of
generation 3. The flag and the benign/attack pairing are new.

---

## 1. The uniform record structure

Every record has the identical shape, so tooling and researchers can treat all
records the same way:

```
CVE-YYYY-NNNNN/
  cvex.yml                  # manifest: images, phases, flag, verification (§4)
  target/
    Dockerfile             # builds the vulnerable service from vendored sources
    vendor/                # pinned sources/binaries — NO network fetch at build time
    plant-flag.sh          # writes the flag into its gated location (§5)
  benign/
    Dockerfile
    interact.sh            # LEGITIMATE use of the same service/endpoints
  attacker/
    Dockerfile
    exploit.sh             # the attack; must retrieve and emit the flag
  recorder/                # shared base image, usually not customized
  dataset/                 # committed reference run (§8)
    benign/   benign.pcap   benign.syscalls.jsonl
    attack/   attack.pcap   attack.syscalls.jsonl
    flag.observed          # the flag as captured by the attack
    verdict.json           # {"success": true, "flag_match": true, ...}
    MANIFEST.sha256
```

Four container roles, one job each:

| Role | Responsibility |
|---|---|
| `target` | runs the vulnerable software; holds the planted flag |
| `benign` | a client that uses the service the way a legitimate user would |
| `attacker` | a client that exploits the service and captures the flag |
| `recorder` | captures packets and system calls for each phase |

A record may add a second target (e.g. a database) when the service needs one;
everything else stays fixed.

---

## 2. The flag (the central mechanism)

The flag is the backbone of the format. It makes success objective, uniform, and
self-labeling.

### 2.1 Definition

A flag is a short token, `CVEX{<32 hex chars>}`, planted inside the `target` at a
location or under a protection that **only the vulnerability can bypass**. Its
secrecy comes from *access control*, not from being unknown:

- a legitimate user of the service cannot reach it;
- the `benign` client never sees it;
- only a successful exploit returns it.

Because the flag is gated by access rather than by randomness, it can be a
**fixed, committed value per record**, which keeps the reference dataset
byte-reproducible. A runner may optionally regenerate it (`--fresh-flag`) to
guard against an exploit that hard-codes the answer; the gating is what proves
exploitation either way.

### 2.2 How the flag is planted and captured, by vulnerability class

This is the part that makes the format general. Each class has a standard
placement and a standard capture channel:

| Vulnerability class | Where the flag is planted | How the attack captures it |
|---|---|---|
| **Remote command exec / injection** (Shellshock, Struts, Log4Shell, elFinder, ThinkPHP, SaltStack, Tomcat JSP, Spring4Shell) | `/flag` in the target, readable only by executing a command on the target | the injected command reads `/flag`; value returns in the response or over a reverse channel |
| **Path traversal / file read / LFI** (Apache 2.4.49/2.4.50, Spring Cloud Config, Ghostcat AJP) | a secret file outside the web root, e.g. `/opt/secret/flag` | the traversal/read request returns the file contents |
| **Arbitrary file upload → RCE** (jQuery File Upload) | `/flag`, reachable once a payload is uploaded and run | the uploaded payload reads `/flag` and returns it |
| **SQL injection** (WP-Advanced-Search) | a row in a table the app never exposes, e.g. `secret.flag` | the injection exfiltrates the row |
| **Privilege escalation** (sudo, sudoedit, bash setuid) | `/root/flag`, mode `0600`, owned by root | escalate, then read `/root/flag` — this *also* resolves the "weak container boundary" worry, because the flag is unreadable without truly becoming root |
| **Local code exec / unsafe deserialization** (Keras, npm `ggit`, gitsome) | `/flag` readable only by the process once code runs, or an env var not exposed by the normal API | the executed code reads and prints the flag |
| **Memory corruption / crash only** (bash redir_stack, CVE-2014-7186) | no secret to read; the "flag" is a **crash marker** — a core dump or an abort of the traced process | the recorder observes the target process crashing; see §2.3 |

### 2.3 The crash-class exception

One of the CVEX records (CVE-2014-7186) is a parser crash with nothing to read. For
crash-class records the flag is replaced by a **crash witness**: the recorder
confirms the traced process terminated by signal / produced a core dump during
the attack phase and did *not* during the benign phase. `cvex.yml` marks this
with `success: crash` instead of `success: flag`. It is the only deviation from
the uniform flag rule, and it is declared explicitly.

### 2.4 Verification

The runner declares success when the **captured flag equals the planted flag**
(or, for crash-class, when the crash witness fires only in the attack phase). The
captured flag is detected on whichever channel the record declares:

- `stdout` — the attacker prints `CVEX_FLAG=<value>` (universal fallback);
- `network` — the flag bytes appear in `attack.pcap` (also serves as proof the
  flag crossed the wire);
- `file` — the attacker writes the flag to a shared volume.

`verdict.json` records the planted flag, the observed flag, the channel, and the
boolean match.

---

## 3. Paired benign / attack capture

Each record is run in two isolated phases, each starting from a **pristine
target** (the container is brought up fresh for each phase, so neither run can
contaminate the other):

1. **Benign phase.** Only the `benign` client runs. It performs *legitimate*
   interactions with the same service and, where possible, the same endpoints the
   attack will touch — a normal login, a normal search, a normal file request, a
   normal use of the tool. The recorder captures `benign.pcap` and
   `benign.syscalls.jsonl`.
2. **Attack phase.** Only the `attacker` client runs. It exploits the service and
   captures the flag. The recorder captures `attack.pcap` and
   `attack.syscalls.jsonl`.

The two captures are directly comparable: same images, same pinned IPs, same
target state at `t=0`. The difference between them *is* the attack signal, which
is exactly what signature generation, anomaly detection, and detection-rule
research need. The flag guarantees the attack capture contains a genuinely
successful exploit, not a failed attempt mislabeled as an attack.

Keeping the phases separate (rather than mixing benign noise into the attack) is
a deliberate choice for clean labels. A future `mixed` phase (benign traffic
concurrent with the attack) can be added without changing the schema.

---

## 4. The `cvex.yml` manifest

```yaml
cvex_version: 3
cve: CVE-0000-00001
topology: target-attacker          # single | target-attacker | target+db-attacker
network:
  subnet: 10.13.0.0/24             # fixed, for reproducible addresses in the pcap

flag:
  value: "CVEX{0000000000000000000000000000demo}"   # fixed & committed (§2.1)
  plant: file:/opt/secret/flag                       # where plant-flag.sh puts it
success: flag                      # flag | crash  (§2.3)
capture:
  flag_channel: network            # stdout | network | file
  tls_intercept: true              # decrypt TLS via mitmproxy on the recorder
  tls_ports: [443]

services:
  target:
    image: cvex/cve-0000-00001-target@sha256:<digest>   # digest-pinned (required)
    ip: 10.13.0.10
    trace: nginx                   # process to syscall-trace (regex)
    ready: "tcp:443"               # runner waits for this before each phase

phases:
  benign:
    client: benign                 # runs benign/interact.sh
    image: cvex/cve-0000-00001-benign@sha256:<digest>
    ip: 10.13.0.30
  attack:
    client: attacker               # runs attacker/exploit.sh, must emit the flag
    image: cvex/cve-0000-00001-attacker@sha256:<digest>
    ip: 10.13.0.20
    trace: curl

limits:
  wall_clock_seconds: 600
```

(The example uses the benign nginx demo that ships with the current tool, so no
real exploit payload appears here.)

Rules enforced at review time:

- every `image` is pinned by `@sha256:` digest;
- `flag.value` and `flag.plant` are present (or `success: crash`);
- `phases.benign` and `phases.attack` are both present;
- IPs are static, so captures are reproducible.

---

## 5. Components

- **`target`** — built from `target/Dockerfile` using only vendored sources
  (`--network=none` for the application layer, §7). `plant-flag.sh` installs the
  flag into its gated location at build or container-start time.
- **`benign`** — `interact.sh` drives legitimate traffic. It is written to touch
  the same surface as the attack so the paired captures are comparable.
- **`attacker`** — `exploit.sh` runs the exploit and emits the captured flag on
  the declared channel. For exploits with a reverse channel, the attacker also
  hosts the listener; the recorder captures both directions.
- **`recorder`** — one shared image. In **sidecar** mode it shares the target's
  network namespace (`network_mode: service:target`, the gen-1 technique) and
  runs `tcpdump`. In **gateway** mode it is the default gateway for the subnet,
  runs `tcpdump` on the bridge, and runs transparent `mitmproxy` with a CA baked
  into the client/target images at build time, so TLS can be decrypted
  reproducibly. It also attaches `strace` to the target's `trace` process to
  produce the syscall logs. Single-host records use sidecar mode; multi-host
  records that need TLS use gateway mode.

---

## 6. Run protocol

`cvex run <record>`:

1. Build (or pull) the pinned images.
2. **Benign phase:** up `target` (+db) + `recorder`; plant the flag; wait for
   `ready`; start capture (benign); run `benign/interact.sh`; stop capture;
   tear down.
3. **Attack phase:** up a *fresh* `target` (+db) + `recorder`; plant the flag;
   wait for `ready`; start capture (attack); run `attacker/exploit.sh`; read the
   emitted flag; stop capture; tear down.
4. **Verify:** compare captured flag to planted flag (or evaluate the crash
   witness). Write `dataset/` and `verdict.json`.

`cvex verify <record>` runs the above and diffs the fresh `dataset/` against the
committed one (flag match + traffic comparison after normalizing packet
timestamps and ephemeral ports). `cvex publish` pushes digest-pinned images to
the registry (ghcr, as in gen 2) so others can run without building.

---

## 7. Reproducibility

1. **Offline, pinned builds** — base images by digest; vulnerable software and
   exploits vendored into the record; the application build runs with
   `--network=none`. A record that cannot build offline is rejected.
2. **Pinned runtime** — static subnet and IPs, fixed `ready` conditions, a wall-clock limit.
3. **Fixed flag** — committed per record (§2.1), so the reference captures are
   byte-stable while still proving exploitation.
4. **Committed reference dataset** — benign and attack captures, syscalls, the
   observed flag, and the verdict, content-addressed by `MANIFEST.sha256`.
   Artifacts survive even if the images can no longer be rebuilt later.

---

## 8. Dataset layout

```
dataset/
  benign/
    benign.pcap             # legitimate traffic (empty/loopback for local records)
    benign.syscalls.jsonl   # syscalls of the traced process under normal use
  attack/
    attack.pcap             # attack traffic; contains the flag if flag_channel=network
    attack.syscalls.jsonl   # syscalls of the traced process during the exploit
  flag.observed             # the flag the attack captured
  verdict.json              # success, flag_match, channel, planted vs observed
  MANIFEST.sha256
```

This paired, flag-verified, content-addressed bundle is the deliverable a
researcher consumes — a labeled benign/attack dataset with a guarantee that the
attack half represents a *successful* exploit.

The status of the existing CVEX corpus and migration notes are tracked
separately in [`CVEX_CORPUS_STATUS.md`](CVEX_CORPUS_STATUS.md).

---

## 9. Known limitations

- **No kernel or Windows coverage** — containers share the host kernel; such CVEs
  stay on the VM framework, which can coexist and share this manifest and dataset
  format.
- **One crash-class record** (CVE-2014-7186) cannot use a read-a-secret flag and
  uses the declared crash witness instead.
- **TLS interception assumes a cooperating trust store** (CA baked into images);
  fine for research reproduction, and noted in each dataset.
- **Benign realism is author-defined** — the quality of the benign baseline
  depends on how representative `interact.sh` is; reviewers should check it
  exercises the same surface as the attack.
- **Timing is not reproducible** — payloads and exchange order are; packet timing
  is normalized away in comparisons.
