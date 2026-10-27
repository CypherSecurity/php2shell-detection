# START HERE — php2shell detection & response package

**CVE-2026-109618 / CVE-2026-109619** · PHP pre-auth RCE + silent memory disclosure
Severity: **CVSS v4.0 9.2 each** (vendor) · **NIST v3.1: 9.8 for 109618, 8.1 for 109619** · Patched **2026-10-21 14:00 UTC**
**Content current as of 2026-10-24 00:00 UTC** · see `BUILD-INFO.md` for what changed and how to verify you have the latest copy


> ## ⚠️ CISA KEV — ACTIVELY EXPLOITED (26 Oct)
> Both CVEs were added to CISA's Known Exploited Vulnerabilities catalog on **2026-10-26**, with a
> **2026-10-29** remediation due date. Separately, a researcher confirmed **working in-the-wild RCE**
> against an Apache mod_php PHP 8.4.26 honeypot (35 shells across three sensors, 24 Oct). This is no
> longer a "not yet exploited" situation.
>
> **Still true:** no named organisation has publicly confirmed a compromise through these CVEs. The one
> reported victim disclosure (Unit 42, 23 Oct) was **retracted by Unit 42 on 25 Oct**. KEV means exploited
> in the wild, not "confirmed victim in your estate".
>
> **Do now:** patch to PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, restart workers, and check PAN-OS,
> Citrix NetScaler and Cisco appliances against `PATCH-AVAILABILITY.md`.

---

## TL;DR for whoever you're sending this to

Two memory-safety bugs **in PHP core itself** — not in WordPress/Laravel/anything.
Any `.php` URL can be attacked **before your application code runs**:

- **CVE-2026-109618** — a fatal error (OOM, timeout) during request setup leaves PHP's
  internal request data half-built; shutdown then treats it as valid → **RCE**
- **CVE-2026-109619** — internal state from one request survives its memory being freed;
  the **next request on the same worker** trusts it → **RCE, or silent heap theft**

**On `display_errors=Off`:** **a public exploit now clears it.** We reproduced `JoasASantos/php2shell-exploit`
on stock PHP 8.4.26 with `php.ini-production` (`display_errors=Off`) on x86-64 and arm64 — and, as of the
**2026-10-26 update**, it also reaches a **default multi-worker Apache prefork pool** — though **unreliably**: benchmark
single-worker **15/15**, multi-worker **2/13**. Worker count is not a control, but it is a strong
reliability factor. Private exploits also exist (VulnCheck x86-64, CovertSwarm AArch64). **Do not rely
on `display_errors=Off`.**

**The silent mode is the part most people miss:** an attacker can steal process memory
(passwords, session tokens, API keys, certificates belonging to *other users'* requests)
**without ever executing code** — the stolen bytes come back inside a `PHPSESSID`
response cookie. No shell, no crash, no child process. Host EDR sees nothing.

**Affected:** PHP 5.4.0 – 8.5.11 (every version since 2012).
**Fixed:** 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.
**EOL (no upstream fix):** PHP ≤ 8.1 — though minimal source backports exist for 7.4/8.0/8.1.

---

## Live status page

A continuously updated public version of this advisory lives at
**<https://f4n6.co.uk/php2shell/>** — regenerated from the same monitoring that produces this package,
so the two cannot drift. Safe to share with customers; it contains no exploit code.

---

## 🚨 If you run Palo Alto PAN-OS or Panorama — read this first (added 2026-10-23)

**PAN-OS / Panorama are affected by both CVEs, no special configuration required.** Fixes are now
**shipping**: 11 hotfix builds released on 25–27 Oct (`10.2.18-h13`, `11.1.16-h4`, `11.2.10-h16`,
`11.1.4-h38`, `11.1.6-h40`, `11.1.10-h36`, `11.1.13-h16`, `10.2.13-h27`, `10.2.16-h12`, `12.1.7-h11`,
`12.2.4-h1`); 9 more on ETA 27–30 Oct. Panorama and
Two of those (`12.1.7-h11`, `12.2.4-h1`) arrived ahead of their ETAs.

**Appliance vendors beyond PAN-OS:** **Citrix NetScaler ADC / Gateway** are impacted and fixes were
published 27 Oct (CTX697263: 14.1-73.49, 13.1-64.32). **Cisco** Expressway fix (15.5.21) is still pending
and URWB is planned for Feb 2027. See `PATCH-AVAILABILITY.md` §8c.

One correction matters here: **WF-500 / WF-500-B are not affected** (vendor corrected its 23 Oct
listing); **Panorama remains affected with no fix date**. PAN rates its product impact **8.7 HIGH**.

- **Do now:** restrict management-interface access (never internet-exposed), and enable the **full
  current Threat Prevention ID list** — **543004, 97622–97625, and the wider set added 24 Oct (`97643`, `97647`, `97649`, `97652`, `97653`, `97656`–`97659`, `97662`–`97664`, `97670`–`97674`, `97676`–`97678`) — content **9162+, 9163, 9164+****. The list grew ~5× on 24 Oct; if you enabled only the
  original five, check your content version and add the rest. These only work if the firewall actually
  inspects management traffic (route MGT via a DP port, replace the inbound cert, decrypt inbound,
  enable threat prevention on management services).
- **Check your branch first** — the 7 released builds cover 11.1.4/6/10/13/16, 11.2.10 and 10.2.18.
- **Do not** assume patching your web servers fixes the firewall — PAN-OS ships its own embedded
  PHP. Only PAN-OS maintenance releases address it.
- **Industrial:** Siemens **RUGGEDCOM APE1808** hosting PAN-OS is affected (SSA-566512) —
  contact Siemens support.
- **Not affected:** **WildFire appliances WF-500 / WF-500-B** (all versions). A 23 Oct revision briefly
  listed them as affected, then corrected it. Do not chase WF-500 fixes.
- **Panorama:** affected, **no published fix date** — plan to stay restricted.
- **Already fixed:** Cortex XCORE (21 Oct), WildFire Cloud (22 Oct).
- **Scope on the device:** the **HTTPS management web UI *and* the XML API**, plus any dataplane
  interface carrying a **management profile**. GlobalProtect portal/gateway are **not** in scope.
- **Impact nuance:** PAN's vector is `VC:N/VI:N/VA:H` — it assesses **outage**, not data compromise,
  and says it is unaware of exploitation against its products. **Public PoCs do not bypass ASLR on
  x86-64**; a working private exploit exists (VulnCheck). Do not assume "public PoC = instant RCE",
  and do not assume "availability only = ignore it".

→ **Exposure numbers, exploit-capability reality, and estate checks: `PAN-OS-EXPOSURE.md`**
→ Patch versions: `PATCH-AVAILABILITY.md` §7b · Dossier §29.

---

## Two questions everyone is asking — answered up front

### Q1: "Is there a second, unpatched PHP vulnerability? My feed says the patch doesn't work."

**No.** The PHP security team formally refuted it on 22 Oct (`oss-security 2026/10/22/15`,
Jakub Zelenka):

> **"This is unrelated issue with minimal impact (crash in one component in slightly unlikely
> scenario). It has nothing to do with the RCE."**

No bypass was demonstrated and PHP published **no re-spin** — 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35
remain current. **Keep patching; there is no "fix to the fix" coming.**

**One honest caveat (added 23 Oct):** PHP has since published an **informational advisory** for a
**third, separate** CVE — **`CVE-2026-115560`** (session upload progress). It is **not** a bypass:
it needs an unusual config (app switches `session.serialize_handler` to `php` at runtime) *plus*
upload progress enabled, PHP calls it an *"unlikely RCE vector"*, and the mitigation —
**`session.upload_progress.enabled=0`** — has been public since 21 Oct and is **already step 1 of
this package's containment order**. If you applied it: no further action. Full fix arrives with the
next regular release.

→ **Full timeline, exact quotes, sources and a paste-ready reply: `CLARIFICATION-second-vulnerability-claim.md`**

### Q2: "Are WE actually patched?"

→ **Version-by-version, distro-by-distro matrix: `PATCH-AVAILABILITY.md`**

Headline as of 2026-10-23: **Ubuntu ✅** (USN-8948-1/-2, including ESM back to 14.04) ·
**Debian 13 ✅** (DSA-6574-1) · **Debian 12 ✅** (DLA-4848-1) · **Docker `php` tags ✅** ·
**RHEL/Remi ⚠️ verify with vendor** · upstream PHP ≤8.1 ⚠️ source backports only.

Two traps that page will catch: **patching WordPress does nothing** (this is PHP, not the app),
and **a package upgrade without a worker restart leaves you exploitable**.

---

## What's in this package

| Folder | Who it's for | What it is |
|---|---|---|
| `01-threat-intel/` | everyone | The dossier: root cause, timeline, IOCs, exploitation analysis |
| `02-detections/` | SOC / detection engineering | Suricata, Zeek, ModSecurity, Sigma, YARA — **ready to deploy** |
| `03-hardening/` | sysadmin / platform | Apache mod_php, PHP-FPM pool, nginx configs |
| `04-hunting/` | threat hunting / IR | 29 Splunk/Elastic/Defender/auditd queries |
| `05-validation/` | skeptics / managers | Lab evidence that these signatures fire on real traffic |

**Start with `02-detections/README.md`** — it has the coverage matrix and deploy order.

---

## 🚨 PUBLIC EXPLOITS — what we have actually TESTED (2026-10-22)

We executed the public PoCs against their own labs. Results:

| Public exploit | Config | Result |
|---|---|---|
| Karasawa `final-zero` | `display_errors=On` | ✅ **RCE CONFIRMED** — `uid=33(www-data)` in **4 HTTP requests**, no auth, no PHP written to target |
| Karasawa `nzd-u8` | `display_errors=Off` | ❌ **NOT reproduced** — fails on its own lab (repo contradicts itself; unverified) |
| 9bie `exploit.py` | `display_errors=On` | ❌ **NOT reproduced** — leak fires (4 KB `PHPSESSID` cookie, `zend_mm_heap corrupted`) but chain fails; calibrated for an older image |
| **Joas `exploit.py`** | **`display_errors=Off`**, `php.ini-production` | ✅ **RCE CONFIRMED** — x86-64 + arm64 (24 Oct); single-worker **15/15**, multi-worker **2/13** (26 Oct benchmark) — `uid=33(www-data)`, independent proof |

**What this means for you:**

1. **Public working RCE is real for `display_errors=On`.** Treat that as fact: patch +
   restart workers.
2. **`display_errors=Off` end-to-end RCE is CONFIRMED (public tool, 24 Oct; multi-worker 26 Oct).**
   Treat production config as exploitable. The heap *disclosure* path (silent memory theft via a
   `PHPSESSID` cookie) is also public.
3. **Public exploit reliability is lower than star counts suggest.** Both failed on
   slightly different environments — they are image/calibration-specific. That reduces the
   predicted rate of mass opportunistic attacks, **not** the risk to a host an attacker has
   specifically calibrated for.

**⚠️ Detection remains the most robust control here.** In our tests the exploits broke on
environment drift while the detectable artefact (`PHPSESSID` cookie anomaly, OOM/log pair)
still appeared. Coverage is environment-independent; exploits are not. Deploy the
detections, especially `DETECTION-MEMORY-DISCLOSURE.md`.

## 🔴 UPDATE 2026-10-22 — EXPLOITED IN THE WILD, POSSIBLY SINCE 17 OCTOBER

Amazon Threat Intelligence (MadPot honeypot network) reports **first PHP2Shell exploitation
attempt on 2026-10-17 — four days before disclosure** — from a commercial anonymisation
network, with **multiple actors** active in the 02:00–08:00 UTC window before the official
14:00 UTC release. AWS now describes the flaws as **"broadly exploited in the wild."**
(Details leaked ~2 days early; PHP accelerated the release to 20 October.)

### Three things this changes in your response

**1. Hunt back to 17 October, not 21 October.**
If your investigation window starts at the patch date, you may miss up to four days of
precursor activity. Run the hunting queries in `04-hunting/hunting-queries-v2.md` across
**2026-10-17 → today**. The behavioural signals are valid across that whole window
regardless of which exploit variant was used.

**2. Treat CISA KEV addition as likely imminent.**
"Broadly exploited in the wild" is close to CISA's own language. Do not wait for the KEV
listing to escalate internally.

**3. This validates behavioural detection over signatures — deliberately.**
AWS's own guidance: *"Invest in detections that don't rely on a signature for a specific
CVE. The first exploitation will often come before those signatures exist."*
The October 17 activity predates any public PoC, so **no CVE signature could have caught
it** — the detections in this package (OOM/log pairing, oversized `PHPSESSID` cookie,
`Session object destruction failed`) are built to work without one.

### Confidence note
Pre-disclosure exploitation is by definition **targeted, not mass scanning**. Targeted
actors are quieter, which raises the relative value of the higher-fidelity, lower-volume
rules here — especially the `PHPSESSID` cookie rule.

## Ubuntu fleets: fixes are available (added 2026-10-23)

Ubuntu shipped **USN-8948-1 / USN-8948-2** (priority: critical). Verified versions:

| Release | Package | Fixed version |
|---|---|---|
| **24.04 noble** | php8.3 | **8.3.6-0ubuntu0.24.04.13** |
| **22.04 jammy** | php8.1 | **8.1.2-1ubuntu2.28** |
| 20.04 focal | php7.4 | 7.4.3-4ubuntu2.29+esm5 *(ESM)* |
| 18.04 bionic | php7.2 | 7.2.24-0ubuntu0.18.04.17+esm14 *(ESM)* |
| 16.04 xenial | php7.0 | 7.0.33-0ubuntu0.16.04.16+esm22 *(ESM)* |
| 14.04 trusty | php5 | 5.5.9+dfsg-1ubuntu4.29+esm18 *(ESM)* |

`sudo apt update && sudo apt install --only-upgrade 'php*'` — then **restart the workers**.
Note the ESM rows: Ubuntu users on EOL releases **do have a supported patch path**, unlike
upstream PHP ≤8.1. That narrows the permanent-exposure population considerably.

## Two clarifications worth knowing (added 2026-10-22 10:55 UTC)

**1. The CVE titles say "PHP 8.2–8.5" — but PHP 7.4, 8.0 and 8.1 are also affected.**
This was raised on oss-security (NVD added it as a reference): the subject line and text can
be read as meaning only 8.2–8.5 are vulnerable. That is misleading. The PHP security team
shipped **minimal source backports for PHP 7.4, 8.0 and 8.1** — which only makes sense if
those branches are affected. So:
- Do **not** treat 7.4/8.0/8.1 hosts as out of scope.
- They get **no official release**; options are a vendor/LTS backport or building from
  source (branches `PHP-7.4/8.0/8.1-CVE-2026-109618-109619`).
- Until then they are permanently exposed and should be prioritised for migration or
  isolation, not just patching.

**2. Active scanners now exist — expect their traffic to hit your detections.**
`assetnote/php2shell-scanner` ("high fidelity scanner") and similar tools let anyone
identify vulnerable hosts at scale. These probe hosts actively and may look like partial
exploitation to your rules.

For **safe inventory of your own estate**, prefer `openai/php2shell-checker` (documented
above) — it determines the PHP version **without sending exploit requests**. If you run an
active scanner internally, expect and allow-list your own detection alerts.

## Do this now (in order)

1. **Patch PHP** → 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
2. **Restart every PHP worker** — `systemctl restart php*-fpm` / `apache2`.
   ⚠️ A *reload* is not enough: the stale state lives in the process. Unrestarted
   workers stay exploitable even after the package upgrade.
3. **If you can't patch yet**, apply `03-hardening/` for your SAPI, at minimum:
   - `memory_limit=-1` + a **cgroup v2 `memory.max`** limit
     (never `RLIMIT_AS`/`RLIMIT_DATA` — those re-create the vulnerable failure)
   - `session.upload_progress.enabled=0`
   - `post_max_size` well below the memory budget
   - lower `pm.max_requests` so workers recycle faster
4. **Deploy detections** in `pass,log` mode first, then promote to block.
5. **Treat any detection hit as a possible confidentiality breach**, not just an
   attempted intrusion — rotate secrets the web user could read (`.env`, DB creds,
   API keys, TLS material) if the memory-disclosure signatures fire.

---

## ✅ Detection validation (2026-10-22 03:55 UTC) — the cookie rule is the key one

A public repo now documents a **working, repeatable heap-disclosure chain that runs with
`display_errors=Off`** — the configuration most hardened production uses. It exfiltrates
~4,000 bytes of process memory (47 pointers per run; documented 3/3 with ASLR off, 2/2 with
ASLR on) inside a **`Set-Cookie: PHPSESSID=` response cookie**, with no crash on a miss.

That is **exactly** what our `PHPSESSID` cookie rule detects — it keys on cookie **length
and character-set anomalies**, not on exploit internals:

> a real PHP session id is 26 chars of `[A-Za-z0-9,-]`; the observed malicious cookie is
> 1,000 prefix chars followed by ~4,000 bytes of decoded heap.

**So for `display_errors=Off` fleets — where public RCE does not yet exist but disclosure
does — this single rule is your primary control.** Deploy it first, in `pass,log`, then
promote to `deny`.

## The three highest-value detections in here

1. **`PHPSESSID` response cookie anomaly** (`02-detections/DETECTION-MEMORY-DISCLOSURE.md`)
   A real PHP session id is 26 chars of `[A-Za-z0-9,-]` and is **never percent-encoded**.
   Any `PHPSESSID` cookie containing `%XX`, non-alphabet bytes, or ≥64 chars is the
   silent heap-theft path. **Near-zero false positives — this is the strongest signal
   in the package.**
2. **Producer → consumer log pair** (`02-detections/sigma/web_php_fatal_corruption_sequence.yml`)
   `Allowed memory size … exhausted … in Unknown on line 0` followed within 60s by
   `Session ini settings cannot be changed when a session is active` **on the same
   worker pid** — the official CVE-2026-109619 signature.
3. **Dangling `PS(save_path)` fingerprint** (same file)
   A session-open failure whose path contains fragments of prior log text. Effectively
   zero false positives; it only happens when session state is corrupted.

---

## Important context (shapes the response)

**This was found by AI.** Wiz (Gemini 4 Argon, GPT-5.6 Sol, Atlas) and Calif/OpenAI
found it in days after it sat undiscovered since **2004** — it was even re-found by a
2024 audit but nobody could prove exploitability. That means:

- The barrier to finding *variants* has dropped permanently. Expect more.
- **93+ GitHub PoC repos appeared within hours** of disclosure, and a probe service
  (`php2shell.site`) is already scanning. Mass exploitation is happening now.
- Public PoCs mostly produce crashes/DoS; working RCE needs per-build tuning. **Do not**
  take "the public PoC doesn't pop a shell" as evidence of safety — the primitive is
  proven and the weaponised chain exists.

---

## What is deliberately NOT in this package

Exploit source code, PoC scripts and working payloads are **excluded** — this bundle is
safe to forward to colleagues, management and customers. If you need to validate
detections against live exploit traffic, do that in an isolated lab against hosts you
own, and ask me separately.

---

## Safe way to find out which hosts are vulnerable (added 2026-10-21 17:55 UTC)

Use **`github.com/openai/php2shell-checker`** (Node.js, no dependencies) — it determines a
host's PHP version **without sending any exploit traffic**:

```sh
node phpcheck.js "https://example.com"   # remote host
node phpcheck.js --local                 # local CLI PHP
```

Exit codes support automation, so this is the low-risk way to build your vulnerable-host
list at scale before patching — far better than running PoCs against production.

**Severity note for reporting:** the vendor (PHP) rates these **CVSS v4.0 9.2** with
attack complexity *High*; NIST/NVD rates **109618 at 9.8 CRITICAL** (`AC:L`) but **re-rated 109619 to 8.1 HIGH** (`AC:H`) on finishing analysis (22 Oct). **Quote per-CVE, not a blanket 9.8.**
Formal CWEs: CWE-416 (use-after-free), CWE-755, CWE-824, CWE-1325.

## Additional authoritative resources (added 2026-10-21 16:55 UTC)

- **NCSC-NL operational repo** (`github.com/NCSC-NL/php2shell`, TLP:CLEAR) —
  includes an **A–Z inventory of PHP-dependent products** (good asset-scoping checklist)
  and a **cPanel/EasyApache 4 mitigation script** for shared-hosting fleets.
  Explicitly states it is being expanded.
- **ENISA consolidated EU CSIRT advisories**: `CNW-2026-04_php`.
- **CERT-EU Advisory 2026-018**.

### ⚠️ Correction (2026-10-21 18:55 UTC): PHP-FPM IS exploitable
Earlier guidance implied mod_php was the exploitable SAPI and FPM only faced DoS. That is
**wrong**. A verified FPM chain exists: an application `session_start()` decoding a large
session OOMs inside `php_var_unserialize`, the FPM worker survives with stale
`BG(unserialize)` state, and a later `upload_progress` request reaches it before request
init → RCE. **FPM is the majority of modern production PHP — do not deprioritise it.**
Watch for the log line `Session object destruction failed` at PHP Request Startup (a new
signature added to the Sigma rules in this package).

### Scope reminder: it is not only web servers
PHP is embedded in **appliances, network devices, management interfaces and vendor
products** where you cannot update PHP directly. Those need **vendor firmware updates**;
until available, isolate their management interfaces from untrusted networks.
Confirmed affected SAPIs: **PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed**
(mod_php = highest risk, exploitable before application code runs).

## Patch status — the "second vulnerability" question is now CLOSED (22 Oct 22:55 UTC)

Say **"patched against CVE-2026-109618 and CVE-2026-109619"** — that is accurate and needs no
hedging.

An unconfirmed report on 21 Oct claimed a *different* PHP vulnerability still worked on 8.5.12.
On 22 Oct the **PHP security team formally refuted it** on oss-security:

> *"This is unrelated issue with minimal impact (crash in one component in slightly unlikely
> scenario). It has nothing to do with the RCE."*

So: **there is no known unpatched second vulnerability in this family.** Patched releases close
the published CVEs.

Keeping the behavioural detections running after patching is still worthwhile — they are cheap
and version-independent — but they are for catching *exploitation of the known bugs on
unpatched hosts*, not an unknown second bug.

## Caveats — please read before quoting numbers

- Detection signatures were **validated in a controlled lab** (Ubuntu 24.04 + PHP 8.3.6
  mod_php; Ubuntu 26.04 + PHP 8.5.4 for the kill/corruption cascade). See
  `05-validation/VALIDATION-REPORT.md` for exactly what reproduced and what did not.
- The **OPcache cross-worker type confusion** variant leaves no reliable wire signature —
  it is hunting-only, which is another reason patching beats detection tuning here.
- YARA session-file rules need filename awareness (`yara -r -g`) or a wrapper that
  pre-filters `sess_*` files.
- Sources: php.net advisory, GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp, Calif
  (`calif.io/php2shell.x/`), Wiz (`wiz.io/blog/php2shell-php-rce`), php2shell.com.