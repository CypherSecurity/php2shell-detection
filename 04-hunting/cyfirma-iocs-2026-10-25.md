# CYFIRMA campaign IoC set — PHP2Shell "suspected DPRK campaign" (v3, 24 Oct 2026)

**Source:** CYFIRMA Threat Advisory v3, *"Suspected DPRK Campaign Staging PHP2Shell Exploitation
Against Global PHP Infrastructure"*, published 23 Oct 2026, v3 24 Oct 2026.
Full report: https://www.cyfirma.com/research/cyfirma-threat-advisory-suspected-dprk-campaign-staging-php2shell-targeting-against-global-php-infrastructure/

**Attribution confidence: MODERATE** (behavioural + linguistic indicators; no infrastructure or
malware-family overlap). Treat as *suspected* DPRK/Lazarus-ecosystem staging, not established.

**Indicators below are defanged** (`[.]`, `hxxp`). CYFIRMA holds an extended set behind DeCYFIR; this is
what is published openly, cross-checked against their Section 09 tables.

> ⚠️ **Read before blocking.** Several of these addresses are shared/anonymising infrastructure
> (VPN/hosting). CYFIRMA's own guidance: *monitor and hunt rather than blind-block*, and investigate a
> sighting before treating it as attribution. A hit means "investigate", not "confirmed compromise".
> Infrastructures of this kind rotate and burn quickly; expect decay within days.

---

## A. Staging / target-list hosting / launch — 15 addresses (+1 possible variant)
**Priority: MONITOR & HUNT.** Shared in a closed I2P channel for staging and launch.

| # | IPv4 | Note |
|---|---|---|
| 1 | `146.70.114[.]180` | staging / target-list hosting / launch |
| 2 | `146.70.114[.]182` | staging / target-list hosting / launch |
| 3 | `147.175.149[.]67` | staging / target-list hosting / launch |
| 4 | `147.78.168[.]57` | staging / target-list hosting / launch |
| 5 | `109.56.219[.]150` | staging / target-list hosting / launch |
| 6 | `158.173.75[.]178` | staging / target-list hosting / launch |
| 7 | `185.203.18[.]54` | staging / target-list hosting / launch |
| 8 | `185.235.212[.]105` | staging / target-list hosting / launch |
| 9 | `103.77.210[.]80` | staging / target-list hosting / launch |
| 10 | `128.90.176[.]13` | staging / target-list hosting / launch |
| 11 | `138.199.34[.]201` | staging / target-list hosting / launch |
| 12 | `145.255.150[.]25` | staging / target-list hosting / launch |
| 13 | `149.102.232[.]44` | staging / target-list hosting / launch |
| 14 | `149.102.232[.]93` | staging / target-list hosting / launch |
| 15 | `158.173.242[.]133` | staging / target-list hosting / launch |
| 16* | `147.78.168[.]67` | *possible actor typo variant of entry 4 — MONITOR only*

## B. Suspected source IPs — web-shell tooling / upload-progress session poisoning (17, 23 Oct)
**Priority: BLOCK or close-monitor at perimeter and host.** Seen in an 8-hour window performing PHP
web-shell tooling and upload-progress session poisoning.

`102.207.250[.]188` · `94.154.43[.]185` · `75.119.143[.]189` · `117.203.73[.]63` ·
`146.190.107[.]103` · `95.217.164[.]124` · `124.122.142[.]142` · `188.80.228[.]122` ·
`134.209.181[.]133` · `134.209.252[.]157` · `119.63.72[.]54` · `138.68.161[.]170` ·
`95.216.5[.]90` · `103.21.161[.]105` · `115.96.27[.]126` · `185.207.232[.]121` · `78.47.85[.]99`

## C. Corroborating open-source exploitation infrastructure
| Indicator | Type | Context | Priority |
|---|---|---|---|
| `92.118.112[.]100` | IPv4 | Dropper staging host (Mirai-style loader) | **BLOCK egress first** |
| `hxxp://92.118.112[.]100/nfs` | URL | Mirai-style loader fetched to `/tmp`, run with arg `php` | **BLOCK egress first** |
| `103.216.220[.]92` | IPv4 | Pre-disclosure exploit attempt, 17 Oct (Amazon MadPot) | MONITOR & HUNT |
| `php2shell-scan/109618` | User-Agent | Leak-derived scanner (Amazon, VulnCheck, ELLIO) | DETECT |
| `php2shell-verify/1.0`, `php2shell-109618` | User-Agent | Same scanner family, verification stage | DETECT |
| `Mozilla/5.0 (php2shell-poc)` | User-Agent | Public-PoC exploitation (VulnCheck, Vega) | DETECT |
| `--p2s…` / `--p2shell` | Multipart boundary prefix | OOM exploit-kit boundary convention (ELLIO) | DETECT |
| `uname -a; id; echo JACKALPOC` | Command / canary | Blind-RCE validation — **`JACKALPOC` in a response = execution** | DETECT |

## D. Malware hashes
| Hash | Type | Family / note |
|---|---|---|
| `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` | SHA-256 | `nfs` second stage — ELF x86-64, stripped, 179,632 bytes |
| `b61a098fc62a2c2696e196dca78da71a` | MD5 | `nfs` second stage |

Request-body hashes (fragile — any boundary/field change defeats them): `43898a0a53bbd25d31ad9f5018ed3182be98a66109b22c9cab545a9fc447992a`,
`7bc41ed79a9ae909927a9e40701736460a8cb70fca16ce1510e58677aca764b6`.

## E. Behavioural / host indicators (highest value — survives IOC rotation)
- Unusual `multipart/form-data` POSTs to non-upload endpoints (e.g. `/`, `/index.php`); `PHP_SESSION_UPLOAD_PROGRESS` in body.
- Web-server processes (php-fpm, php-cgi, httpd, apache2, lsphp) spawning shells/interpreters/download tools (`sh`, `bash`, `curl`, `wget`, `nc`, `busybox`) or executing from `/tmp`, `/var/tmp`, `/dev/shm`.
- New or modified `.php` / `.phtml` / `.phar` files in web roots; `.user.ini` / `.htaccess` with `auto_prepend_file`.
- Outbound connections from web workers to hosting/VPS ranges; I2P egress.
- Credential-store access from web-server context (hashes, MFA secrets), NTLM relay / anonymous LDAP to DC (Unit 42 intrusion pattern).

---

## What we added to the detection set because of this
Three Suricata rules (validated, exit 0):

| SID | Detection |
|---|---|
| 2202610118 | Request UA contains `php2shell-` (scanner family: `-scan`, `-verify`, `-poc`, `-109618`) |
| 2202610119 | Response body contains `JACKALPOC` — **blind-RCE canary: a hit means code executed** |
| 2202610120 | Egress to `92.118.112.100` URI `/nfs` (Mirai-style loader fetch) |

**Why two of these matter more than an IP list:** the user-agent family and the `JACKALPOC` canary
survive infrastructure rotation. The IPs are ephemeral and shared; use them for hunting/pivoting, not
as a security control.

## Caveat on vendor IoCs
CYFIRMA's attribution is moderate confidence and its own guidance is to investigate before blocking.
Two of their quoted scanner user-agents overlap with *defensive* scanning reported by Amazon/VulnCheck —
so a UA hit can be a researcher as easily as an attacker. Correlate with request shape (multipart to
non-upload endpoint, upload-progress field) before escalating.
