# Authoring a CVEX v3 record from a curated scaffold (tier E)

This guide is for turning the **14 curated scaffolds** (records migrated from the
historical gen-3 Vagrant corpus) into full, verified, conformant CVEX v3 records.
Each is a good per-person assignment: the hard parts (which software, which
version, the exploit) are already preserved in the record's `_source/`.

Worked reference: **`CVEX-records/CVE-2014-6271`** (Shellshock) — read it alongside
this guide; everything below is exactly how it was built.

---

## What you start with

Each scaffold has a `_source/` holding the gen-3 original:

```
_source/
  cvex.yml              # gen-3 manifest: blueprint (1 host = single, 2 = target-attacker)
  ubuntu1.yml ubuntu2.yml   # Ansible playbooks: how the target was built + run
  data/                 # the source tarballs, configs, AND usually the exploit script
```

The playbooks and `data/` tell you: the vulnerable software + version, its config,
and (in `data/`, most of the time) the exploit the original used. Your job is to
re-express that as a self-contained, offline CVEX record.

## What you must produce (a conformant record passes `tools/cvex_check.py`)

```
cvex.yml              topology, flag, success:flag, build.offline:true, @sha256 image pins
target/               Dockerfile (offline build), vendor/ (checksummed), plant-flag.sh
benign/  attacker/     Dockerfile + interact.sh / exploit.sh  (+ vendor/debs for curl)
recorder/             Dockerfile + capture.sh
compose.yml           reference compose
dataset/              produced by `cvex_run.py` (committed): paired pcap + syscalls, verdict
```

## The flag rule

Plant a world-readable `/flag` (or `/opt/secret/flag` for file-read bugs; `/root/flag`
mode 0600 for privesc). It must be reachable **only** by the vulnerability — a normal
request never returns it. The attacker makes the vulnerability read `/flag` and the
value comes back on the chosen channel (`network` = it appears in `attack.pcap`;
`stdout` = the attacker prints `CVEX_FLAG=<value>`).

---

## Step by step

1. **Read `_source/`.** Identify the software+version, the exploit in `data/`, and the
   topology (`blueprint` with two hosts → `target-attacker`).

2. **Vendor what the target needs** (so the build is offline). Use the helper:
   ```
   sh tools/cvex_vendor_debs.sh <debian:12-slim@sha256:…> .vend/<name> <pkg>...
   ```
   Reusable bundles already exist under `.vend/`: `build` (build-essential), `apache2`,
   `client` (curl), `recorder` (tcpdump+strace). Copy them into `target/vendor/…` and
   write a `SHA256SUMS` over every vendored file.

3. **Write `target/Dockerfile`** — pinned base `FROM …@sha256:`, install from
   `vendor/` only (verify with `sha256sum -c`), **no network fetch**. Build the
   vulnerable binary from source in a build stage when needed (bash, sudo, …), then
   copy it into the runtime stage. Plant the flag. Start the service in the foreground.

4. **`attacker/exploit.sh`** — port the exploit from `_source/data/`. Point its command
   at `/flag` (e.g. Shellshock's `/bin/cat /flag`) and emit `CVEX_FLAG=<captured>`.
   *Do not write a new exploit* — reuse the shipped one, or a public PoC, adapted only
   to read the flag.

5. **`benign/interact.sh`** — exercise the *same* endpoint legitimately (the fair
   counterpart to the attack; it must never obtain the flag).

6. **`recorder/`** — copy `capture.sh` from any finished record; `trace:` in `cvex.yml`
   names the target process to strace (e.g. `apache2`, `java`).

7. **Verify and check:**
   ```
   python3 tools/cvex_run.py CVEX-records/<CVE> --pin   # build offline, run both phases, capture, verify
   python3 tools/cvex_check.py CVEX-records/<CVE>        # must PASS
   ```
   `--pin` writes the built image ids into `cvex.yml`. On success the record self-locks.

---

## Gotchas (all hit while building the worked examples)

- **Apache in a minimal image**: create `/var/run/apache2/socks` (else `mod_cgid`
  can't bind its socket → 503), source `/etc/apache2/envvars`, run foreground.
- **`flag travels in the attack pcap` fails** though the exploit works: the request
  finished before capture went live. Have `exploit.sh` **re-send the flag request a
  few times** after it succeeds (see Shellshock / Tomcat).
- **HTML-escaped flag**: some apps escape `{` as `&#123;` in the response, so `CVEX{…}`
  never appears verbatim — parse `CVEX(\{|&#123;)[0-9a-f]{32}` and reconstruct, and use
  the `stdout` channel if the literal flag can't cross the wire (see XWiki, CVE-2025-24893).
- **DB-backed apps**: the runner starts the db first and passes its alias/env from
  `cvex.yml` (`services.db.alias`, `environment`); give a `db_warmup_seconds` if it
  imports a dump. Pre-bake interactive setup state into the images (see XWiki).
- **Old source won't `./configure`/`make`** under modern gcc: usually fine for bash/sudo;
  if not, add the needed `-dev` deb or a small patch, and document it.
- **Big syscall logs**: the runner gzips traces >20 MB automatically.

---

## Assignment table (the 13 remaining)

Topology: all `target-attacker` except the two privesc ones (`single`). "Exploit in
`_source`" means you port it rather than find one.

| CVE | Software | Class | Exploit in `_source/data/` | Notes / difficulty |
|---|---|---|---|---|
| CVE-2014-6271 | Apache + bash 4.2 | Shellshock RCE | ✅ `exploit.sh` | **DONE — worked example** |
| CVE-2017-9805 | Struts 2.5.10 / Tomcat | REST XStream RCE | ✅ `struts-pwn` | build Tomcat + Struts app; medium |
| CVE-2018-20062 | ThinkPHP 5.0.23 | RCE | ❌ (use public PoC) | PHP; medium |
| CVE-2018-9206 | jQuery File Upload | upload → RCE | ✅ `CVE-2018-9206.sh` | has `jquerydocker/`; medium |
| CVE-2019-18276 | bash 5.0 (setuid) | **privesc** (single) | ✅ `bash50patch11-escalate.sh` | build bash 5.0; flag `/root/flag` 0600 |
| CVE-2020-16846 | SaltStack | RCE | ✅ `setup.sh` (+`salt`,`v3002.zip`) | salt-api; medium-hard |
| CVE-2020-1938 | Tomcat 9.0.30 (AJP) | Ghostcat file read | ✅ `…Ajp-lfi.py` | flag `/opt/secret/flag`; file-read channel |
| CVE-2020-5405 | Spring Cloud Config | path traversal | ❌ (use public PoC) | Java/maven (`m2.tar`); medium |
| CVE-2021-32682 | elFinder | RCE | ✅ `exploit.py` (+`elfinder.tar`) | PHP; medium |
| CVE-2021-34081 | gitsome | RCE | ✅ `exploit.py`,`poc.js` | **single**-ish; node/python |
| CVE-2021-44228 | Log4j / JDK 8u20 | **Log4Shell** RCE | ✅ `log4j-shell-poc/` | needs an LDAP+HTTP stager; hard |
| CVE-2022-22965 | Spring Framework | **Spring4Shell** RCE | ❌ (`spring4shell/` context) | Java; hard |
| CVE-2024-6205 | WP + PayPlus plugin | RCE | ✅ `exploit.py` | needs WP + MySQL (`target+db`); hard |
| CVE-2024-9796 | WP + WP-Advanced-Search | SQLi | ✅ `exploit.py` | needs WP + MySQL (`target+db`); hard |

Good first picks after Shellshock: **CVE-2019-18276** (single-host bash privesc, like
the sudo gold records) and **CVE-2020-1938** (Ghostcat file-read, like the httpd
records). The WordPress and Log4Shell ones are the hardest (multi-service / staged).
