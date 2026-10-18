# CVEX Corpus Status

This note tracks how the existing CVEX corpus relates to the CVEX v3 format.
The format itself is defined in [`CVEX_v3_DESIGN.md`](CVEX_v3_DESIGN.md).

---

## 1. Feasibility over the 24 existing records

Every record needs three things to fit the format: a Docker build, a benign
interaction, and a flag. Columns below: **class**, **flag** (planting →
channel), **benign interaction**, **network traffic?**

| CVE | Class | Flag plant → channel | Benign interaction | Net |
|---|---|---|---|---|
| CVE-2014-6271 | RCE (CGI) | `/flag` → network | normal CGI request | ✅ |
| CVE-2015-1427 | RCE (Elasticsearch) | `/flag` → network | normal `_search` query | ✅ |
| CVE-2017-12617 | RCE (Tomcat JSP) | `/flag` → network | normal GET of an app page | ✅ |
| CVE-2017-9805 | RCE (Struts) | `/flag` → network | normal REST request | ✅ |
| CVE-2018-20062 | RCE (ThinkPHP) | `/flag` → network | normal page view | ✅ |
| CVE-2018-9206 | upload→RCE | `/flag` → network | normal file upload | ✅ |
| CVE-2020-16846 | RCE (SaltStack) | `/flag` → reverse channel | normal salt-api call | ✅ |
| CVE-2020-1938 | file read (AJP) | secret file → network | normal HTTP request | ✅ |
| CVE-2020-5405 | file read (Spring) | secret file → network | normal config fetch | ✅ |
| CVE-2021-32682 | RCE (elFinder) | `/flag` → network | normal file-manager op | ✅ |
| CVE-2021-34081 | RCE (gitsome) | `/flag` → stdout | run tool on a benign repo | ❌ |
| CVE-2021-41773 | path traversal/RCE | secret file/`/flag` → network | normal GET | ✅ |
| CVE-2021-42013 | path traversal/RCE | secret file/`/flag` → network | normal GET | ✅ |
| CVE-2021-44228 | RCE (Log4Shell) | `/flag` → reverse channel | normal login POST | ✅ |
| CVE-2022-22965 | RCE (Spring4Shell) | `/flag` → network | normal greeting request | ✅ |
| CVE-2024-6205 | RCE (WP plugin) | `/flag` → network | normal plugin use | ✅ |
| CVE-2024-9796 | SQLi (WP plugin) | secret row → network | normal search | ✅ |
| CVE-2019-14287 | privesc (sudo) | `/root/flag 0600` → stdout | authorized sudo use | ❌ |
| CVE-2019-18276 | privesc (bash) | `/root/flag 0600` → stdout | normal shell session | ❌ |
| CVE-2023-22809 | privesc (sudoedit) | `/root/flag 0600` → stdout | authorized sudoedit use | ❌ |
| CVE-2024-21532 | cmd injection (npm) | `/flag` → stdout | run tool on benign input | ❌ |
| CVE-2024-21533 | cmd injection (npm) | `/flag` → stdout | run tool on benign input | ❌ |
| CVE-2024-3660 | deserialization (Keras) | `/flag` → stdout | load a benign model | ❌ |
| CVE-2014-7186 | **crash (bash)** | **crash witness** (design §2.3) | normal shell parse | ❌ |

**Counts**

- **All 24 fit the format.** 23 use the uniform flag mechanism; 1 (CVE-2014-7186)
  uses the design's declared crash-witness variant.
- **16 of 24 are multi-host and produce paired benign/attack *network* captures**
  (pcap). These are the richest for the traffic-focused goals: labeled benign vs.
  attack packets over the same service, with the flag visible in the attack pcap
  for the `network`-channel cases. (Two of the 16, the WordPress records, add a
  database container but are still attacker-over-network-to-target.)
- **8 of 24 are single-host** (4 privilege escalation, 3 local code/injection,
  and the 1 crash record). They produce no network pcap, so their paired dataset
  is benign vs. attack **system calls**.
- **The 4 privilege-escalation records gain the most from the flag:** planting
  `/root/flag` at mode `0600` turns the earlier "root-in-a-container is a weaker
  boundary" caveat into a non-issue — the flag is simply unreadable unless the
  escalation genuinely succeeds.
- **5 records already ship a Dockerfile** (CVE-2015-1427, CVE-2018-9206,
  CVE-2021-32682, CVE-2021-44228, CVE-2022-22965), so their `target` is largely
  done.

So: **24/24 reproducible in the new format; 16 yield paired benign/attack network
captures; all 24 yield paired benign/attack syscall captures; 23 are verified by
a captured flag and 1 by a crash witness.**

---

## 2. Beyond the 24 (the wider corpus)

The other repositories hold **57 more distinct CVEs already in a Docker form**
(51 in `CVEX-legacy`/`CVEX-build`, 6 in `cvex-xplor`), for **78 distinct CVEs**
in all (overlap with the 24 is only CVE-2014-6271, CVE-2015-1427, CVE-2021-41773).
Those 57 do not need re-platforming — they are already containers — but to join
this format they need the two new pillars added: a **flag** (most have only a
`touch /tmp/...` style check today) and a **benign phase** (none capture benign
traffic). Their existing `collector`/tcpdump sidecar and `exploit_verification`
make them a short step from compliance; the main practical blocker is that their
images point at registries that may no longer resolve
(`cvex.cs.ucsb.edu`, `registry.trickel.com:9040`, some `ghcr.io/ucsb-seclab/*`),
so they must be rebuilt from vendored sources regardless.
