# PATCH AVAILABILITY — php2shell (CVE-2026-109618 / CVE-2026-109619)

**Verified from primary sources on 2026-10-23.** This is the "are we actually patched?" page.

> ⚠️ **Two rules before the tables:**
> 1. **"Patched" = fixed package installed **AND** PHP workers restarted.** Stale worker state
>    survives a package upgrade; an upgraded-but-not-restarted host is **still exploitable**.
> 2. **Patching the application does nothing.** This is a bug in **PHP itself**. WordPress,
>    Drupal, Laravel, Magento, cPanel and plugin updates do **not** fix it — the PHP runtime
>    must be updated.

---

## 0. URGENCY CHANGE (2026-10-27): CISA KEV listed, exploitation confirmed

CISA added **CVE-2026-109618** and **CVE-2026-109619** to the KEV catalog on **2026-10-26** (catalog
2026.10.26) with a **2026-10-29** due date. US federal civilian agencies are bound by that date; for
everyone else it is a strong statement that working exploitation is happening. A researcher also
confirmed working RCE on an Apache mod_php PHP 8.4.26 honeypot (35 shells across three sensors on 24 Oct,
matching the single-worker profile we benchmarked). No named victim organisation is confirmed.

Patch priority is now: (1) PHP runtimes, (2) every embedded-PHP appliance with an exposed management
plane (PAN-OS, Citrix NetScaler, Cisco Expressway), (3) worker restarts everywhere you patched.

## 1. Upstream PHP — official releases (2026-10-21)

| Branch | Fixed version | Notes |
|---|---|---|
| 8.5 | **8.5.12** | |
| 8.4 | **8.4.27** | |
| 8.3 | **8.3.36** | |
| 8.2 | **8.2.35** | Minimum supported branch |

## 2. End-of-life branches — no official release

| Branch | Status |
|---|---|
| **8.1 / 8.0 / 7.4** | **Affected.** No official release. PHP published **minimal source backports** in branches `PHP-7.4-CVE-2026-109618-109619`, `PHP-8.0-…`, `PHP-8.1-…`. You must build from source, or use a distro/LTS backport (Ubuntu ESM and Debian LTS both ship one — see below). |
| ≤ 7.3 | Affected, **no backport**. Migrate or isolate. |

## 3. Ubuntu — USN-8948-1 / USN-8948-2 (priority: critical) ✅

| Release | Package | Fixed version |
|---|---|---|
| **24.04 noble** | php8.3 | **8.3.6-0ubuntu0.24.04.13** |
| **22.04 jammy** | php8.1 | **8.1.2-1ubuntu2.28** |
| 20.04 focal | php7.4 | 7.4.3-4ubuntu2.29+esm5 *(ESM)* |
| 18.04 bionic | php7.2 | 7.2.24-0ubuntu0.18.04.17+esm14 *(ESM)* |
| 16.04 xenial | php7.0 | 7.0.33-0ubuntu0.16.04.16+esm22 *(ESM)* |
| 14.04 trusty | php5 | 5.5.9+dfsg-1ubuntu4.29+esm18 *(ESM)* |

```sh
sudo apt update && sudo apt install --only-upgrade 'php*'
sudo systemctl restart apache2   # and/or php*-fpm
```
**Note the ESM rows:** Ubuntu users on EOL releases **do have a supported patch path** — this is
not a "no fix available" situation.

## 4. Debian ✅ (both current branches now fixed)

| Release | Package | Fixed version | Advisory |
|---|---|---|---|
| **trixie (13)** | php8.4 | **8.4.27-1~deb13u1** | **DSA-6574-1** |
| **bookworm (12)** | php8.2 | **8.2.35-1~deb12u1** | **DLA-4848-1** |
| sid | php8.4 | 8.4.27-1 | — |
| forky (14) | php8.4 | 8.4.26-1 — **still vulnerable** | — |

⚠️ **Debian 12 bookworm is now fixed** (security pocket). It was *not* fixed on 21–22 Oct; if
your notes say otherwise, they are out of date.

## 5. RHEL / CentOS / Alma / Rocky — verify with your vendor ⚠️

**Not independently verified at publication time.** What is known:
- The **Remi repository** (`rpms.remirepo.net`) — very common on RHEL-family hosts — did **not**
  publish the fix on 21 Oct; the PHP Foundation indicated the volunteer-run repo would not ship
  that day.
- Distribution PHP packages (if you use them) follow your distro's advisory stream.

**Action:** check the package *origin* on each host (`rpm -qi php`), not just the version
string — a host can look patched and still be running Remi bits, or vice versa.

## 6. Containers — official `php` images published 2026-10-21 ✅

Verified present on Docker Hub: **`php:8.5.12-apache`**, **`php:8.4.27-apache`**,
**`php:8.3.36-apache`**, **`php:8.2.35-apache`** (all published 2026-10-21).

⚠️ **Base-image drift caution:** the floating `php:8.4.x-apache` tag has moved from Debian 12
to Debian 13 in recent builds, which changes glibc and therefore heap behaviour. Pin an explicit
tag (and ideally a digest) rather than tracking a floating tag.

## 7. Applications do not need patching — the runtime does

| You run | What to patch |
|---|---|
| WordPress / Drupal / Joomla / Magento | **PHP runtime only.** No plugin/theme/core update addresses this. |
| Laravel / Symfony / generic PHP apps | **PHP runtime only.** |
| cPanel / Plesk / shared hosting | Your provider must update the PHP packages; check cPanel's EasyApache 4 PHP versions. |
| Appliances / vendor products bundling PHP | **Vendor firmware.** You cannot patch PHP yourself — isolate management interfaces meanwhile. |

## 8. Verify a host (copy-paste)

```sh
# 1. What PHP is actually serving requests? (CLI version can differ!)
curl -s http://localhost/phpinfo-check.php | grep -o 'PHP Version [0-9.]*'
# or
php -v | head -1

# 2. Is it at a fixed level?
#    8.5 >= 8.5.12 | 8.4 >= 8.4.27 | 8.3 >= 8.3.36 | 8.2 >= 8.2.35

# 3. Has the worker been restarted since the package upgrade? (compare times)
systemctl show -p ActiveEnterTimestamp php8.3-fpm apache2 2>/dev/null

# 4. Debian/Ubuntu package state
dpkg -l | grep -E '^ii\s+php' | awk '{print $2, $3}'
#    then compare against the tables above
```

## 7b. ⚠️ Palo Alto Networks PAN-OS / Panorama — affected; **fixes now shipping (since 25 Oct)**

PAN-OS and Panorama are **affected** by both CVEs, with **no special configuration required**.
**Fixed versions are not released yet** — ETAs **26–30 Oct 2026**. PAN rates its own product impact
**CVSS-B 8.7 HIGH** (suggested urgency: MODERATE).

| Branch | Fixed (pending) | ETA |
|---|---|---|
| 12.2 | `12.2.4-h1` (**released 27 Oct**) | — |
| 12.1 | `12.1.7-h11` (**released 27 Oct**) / `12.1.4-h13` / `12.1.10-h3` | 10/29 – 10/30 for the rest |
| 11.2 | `11.2.10-h16` / `11.2.13-h4` / `11.2.16-h1` / `11.2.7-h23` / `11.2.4-h23` | 10/26 – 10/30 |
| 11.1 | `11.1.16-h4` … `11.1.7-h12` | 10/26 – 10/30 |
| 10.2 | `10.2.13-h27` / `10.2.16-h12` (**released 27 Oct**) / `10.2.10-h42` / `10.2.7-h39` | 10/29 – 10/30 for the rest |


**UPDATE 2026-10-26 — hotfixes have begun to ship.** Palo Alto's advisory carries its own timeline:
*"2026-10-26 Removed the ETAs for 11.1.4-h38, 11.1.6-h40, 11.1.10-h36 and 11.1.13-h16 as these versions
are released"* and *"2026-10-25 … removed the ETA for 10.2.18-h13, 11.1.16-h4 and 11.2.10-h16 as these
versions are released"*. PAN-OS release notes confirm each build "includes a fix to address
CVE-2026-109618".

| Status | Builds |
|---|---|
| **Released 25 Oct** | `10.2.18-h13` · `11.1.16-h4` · `11.2.10-h16` |
| **Released 27 Oct** | `10.2.13-h27` · `10.2.16-h12` · `12.1.7-h11` · `12.2.4-h1` |
| **Released 26 Oct** | `11.1.4-h38` · `11.1.6-h40` · `11.1.10-h36` · `11.1.13-h16` |
| Still pending (ETA) | `11.1.7-h12` (10/30) · `11.2.4-h23` (10/30) · `11.2.7-h23` (10/29) · `11.2.13-h4` (10/27) · `11.2.16-h1` (10/28) · `10.2.7-h39` (10/30) · `10.2.10-h42` (10/29) · `12.1.4-h13` (10/29) · `12.1.10-h3` (10/30) |

**Action:** if your branch has a released build, upgrade now (maintenance window, then verify the
management interface is reachable only from trusted sources). Branches still pending keep the interim
controls below. **Panorama** still has no announced fix date. **WF-500 / WF-500-B are not affected**
(vendor correction, 23 Oct; verified 26 Oct). Confirm build existence on the
advisory page before scheduling — PAN revises ETAs.

**Interim mitigations (for branches without a released fix):**
1. **Restrict management-plane access** — never expose the MGT interface to the internet.
2. Enable the **full current** Threat Prevention ID list — **543004, 97622–97625, and the wider set added 24 Oct (`97643`, `97647`, `97649`, `97652`, `97653`, `97656`–`97659`, `97662`–`97664`, `97670`–`97674`, `97676`–`97678`) — content **9162+, 9163, 9164+****. ⚠️ **Updated 24 Oct:** the list
   grew from 5 to 25 signatures; enabling only the original five leaves you under-covered. Verify the
   content version is **≥9164**.
   These only help if the firewall sees management traffic: route MGT through a DP port, replace
   the inbound management certificate, **decrypt inbound management traffic**, and enable threat
   prevention on management services.
3. **Frontier Virtual Patching (ATP Plus)** on PAN-OS 12.2.4+ — Threat ID 543004.

**Not affected:** GlobalProtect App, Prisma (Access/Cloud/SD-WAN), Cortex XDR/XSIAM/XSOAR/Xpanse,
Cloud NGFW. **Already remediated:** Cortex XCORE (21 Oct), WildFire Cloud (22 Oct).

**Not affected (corrected 23 Oct):** **WildFire appliances WF-500 / WF-500-B** (all versions). Earlier
23 Oct text listed them as affected; the vendor corrected this the same day. Also affected:
**Panorama** (all versions) — **no published fix date for either**. Plan for restricted management
access indefinitely rather than waiting for a release.

**Scope:** the HTTPS management web UI **and the XML API service**, plus dataplane interfaces that
carry a **management profile**. GlobalProtect portal/gateway and captive portal are **not** affected.

**Impact note:** PAN's vector is `VC:N/VI:N/VA:H` — it assesses **outage**, not data compromise, and
says it is unaware of exploitation against its products. Public PoCs do **not** bypass ASLR on
x86-64; a private working exploit exists. See `PAN-OS-EXPOSURE.md`.

**Industrial:** Siemens **RUGGEDCOM APE1808** hosting PAN-OS is affected (**SSA-566512**) — contact
Siemens support; no self-service fix.

**Note:** you cannot patch the appliance's embedded PHP — only PAN-OS maintenance releases apply.


## 8c. Appliance and platform vendors beyond PAN-OS (added 2026-10-27)

Several appliance vendors embed PHP. These are the ones with published php2shell positions. Check the
vendor advisory before acting, because fixed "releases" are sometimes future plans rather than downloads.

### Citrix NetScaler ADC / NetScaler Gateway — IMPACTED, fixes published 27 Oct

Advisory: **CTX697263**, *"Citrix Security Advisory for CVE-2026-109618 and CVE-2026-109619"*, severity
critical, created 22 Oct, **updated 27 Oct** (remediation versions updated). NetScaler ADC and NetScaler
Gateway are impacted.

| Product | Fixed versions |
|---|---|
| NetScaler ADC / Gateway 14.1 | **14.1-73.49** and later |
| NetScaler ADC / Gateway 13.1 | **13.1-64.32** and later 13.1 releases |
| NetScaler ADC 14.1-FIPS | **14.1-73.49 FIPS** and later |
| NetScaler ADC 13.1-FIPS / 13.1-NDcPP | **13.1.37.286** and later |

Not impacted (vendor list): NetScaler Console, Citrix Analytics, Endpoint Analysis, Endpoint Management,
Observability, Secure Access, Secure Private Access, Session Remote Start, Virtual Apps and Desktops,
Workspace App, StoreFront, Provisioning, eLux Scout, XenServer. Citrix-managed cloud services were
remediated before publication, so cloud customers need no action.

Citrix's mitigation guidance is again about **management access**: restrict the management interface to
trusted networks until the fixed build is installed. Treat a NetScaler management interface the same way
you would treat PAN-OS MGT.

### Cisco — PARTLY AFFECTED, mostly fixes not yet available

Advisory: *"Vulnerabilities in PHP Affecting Cisco Products: October 2026"*
(cisco-sa-php-october26-Jj384Daq), last updated 26 Oct. Cisco's rule: a product not listed is not affected.

| Cisco product | Bug | Fixed release |
|---|---|---|
| Expressway Series / Expressway Select Series | CSCwx37062 | **15.5.21**, availability date TBD |
| Ultra-Reliable Wireless Backhaul (URWB) | CSCwx37073 | **27.1.1**, planned Feb 2027. Requires administrator authentication, CVSS 6.6, workaround available |
| Duo Access Gateway | — | **3.2.0** (released) |

Cisco lists workarounds in the relevant bug IDs. Planned release versions are not downloads: confirm in the
Cisco download channel before scheduling.

### Siemens RUGGEDCOM APE1808 (with PAN-OS) — affected; remediate via PAN-OS

Advisory **SSA-566512** (published 2026-10-23, V1.0): **RUGGEDCOM APE1808** devices running PAN-OS are
affected in **every listed PAN-OS branch: 10.2, 11.1, 11.2, 12.1, 12.2**. Siemens directs customers to the
Palo Alto Networks advisories and workarounds; there is no separate Siemens firmware fix listed in V1.0. In
practice the PAN-OS fix chain in section 7b is the remediation, and the APE1808 must follow its branch's
PAN-OS release.

Why this matters for scanning: NVD added Siemens CPE entries (`ruggedcom_ape1808_firmware`,
`ruggedcom_ape1808`) to both CVEs on 2026-10-28, so CPE-based scanners will flag these industrial edge
devices. They are PAN-OS hosts, not a separate PHP runtime.

### Other vendor positions worth checking (not tracked in detail here)
Red Hat, Ubuntu, Debian, cPanel, Plesk, Sophos and Veeam have published positions; the distributions are
covered in sections 3 to 5 above. Broadcom has a portfolio response with isolated affected products
(Symantec Endpoint Protection Manager, Carbon Black App Control Server, CloudSOC SpanVA). If your estate
includes an appliance not listed here, the vendor advisory is the only reliable source.

## 8b. CVE-2026-115560 — no patch yet; mitigate by configuration

PHP published an **informational advisory** on 2026-10-23 (session upload progress) assigning
**CVE-2026-115560**. **There is no patch yet** — it is queued for the next regular release.

**Only relevant if all three are true:** `session.serialize_handler` is set to `php_binary` or
`php_serialize` in config, the application switches it to `php` at runtime with `ini_set()` before
`session_start()`, and `session.upload_progress.enabled` is on.

**Mitigation (public since 21 Oct):** set `session.upload_progress.enabled=0`. This is already
step 1 of the containment order in `06-soc-triage/INCIDENT-RESPONSE.md` — **if you applied it,
nothing further is required.** PHP describes the issue as an *"unlikely RCE vector"* and notes that
apps which never change the serialize handler at runtime can leave upload progress enabled.

**This is not a bypass of the 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 fixes** — see
`CLARIFICATION-second-vulnerability-claim.md` §6.

## 9. Fleet status summary (2026-10-23)

| Population | Status |
|---|---|
| Upstream PHP 8.2–8.5 | ✅ fixed |
| Upstream PHP 7.4 / 8.0 / 8.1 | ⚠️ source backports only |
| Upstream PHP ≤ 7.3 | ❌ no fix — migrate/isolate |
| **Ubuntu (all supported + ESM)** | ✅ **fixed — USN-8948-1/-2** |
| **Debian 13 trixie** | ✅ fixed — DSA-6574-1 |
| **Debian 12 bookworm** | ✅ **fixed — DLA-4848-1** |
| Debian forky (14) | ❌ still vulnerable |
| RHEL family / Remi | ⚠️ **verify with vendor** |
| Official Docker `php` images | ✅ fixed tags available (2026-10-21) |
| Appliances embedding PHP | ⚠️ vendor firmware only |

**Sources:** php.net release announcements; Ubuntu CVE tracker + USN-8948-1/-2; Debian Security
Tracker (DSA-6574-1, DLA-4848-1); Docker Hub `library/php`; PHP advisory GHSA-w8hw-w9fx-j79w /
GHSA-6wmf-4rv5-p3rp.


## 10. Known regression introduced by the fixed releases (2026-10-24)

The 21 October security releases changed the garbage collector. **8.4.27 and 8.5.12 introduce a
double-free in SimpleXML**: when an object converted via `json_encode()`, `(array)` or
`get_object_vars()` (i.e. the everyday `json_decode(json_encode($xml), true)`) is collected in a
reference cycle, PHP aborts the worker with `zend_mm_heap corrupted`.

| | |
|---|---|
| Upstream issue | [php-src#24488](https://github.com/php/php-src/issues/24488) — closed, `Status: Verified` |
| Affects | PHP 8.4.27 and 8.5.12 (introduced by the security release); 8.3.36 / 8.2.35 not affected by this change |
| Impact | Availability only — crashed worker, no memory corruption primitive demonstrated |
| Fix | Merged upstream, **not in any released build** as of 24 October |
| What to do | Stage the upgrade; search for the conversion pattern on SimpleXML objects; know the crash signature. **Do not roll back to a vulnerable PHP build.** |

## 11. Community mitigation for hosts that cannot patch (third-party)

`HOSTED-POWER/php_uploadprogress_guard` — a native PHP extension that mirrors the official fix for
CVE-2026-109618/109619 on unpatched PHP, forces `session.upload_progress.enabled=0` (covering
CVE-2026-115560), and applies upstream fixes for two unrelated PHP bugs by patching from inside the
extension. Prebuilt for Linux x86_64/aarch64 and Windows x64, with checksums.

**Caveats:** third-party native extension loaded into the web server — supply-chain and stability
risk. It is **not** a substitute for the official fixed builds. Recommended only where patching is
genuinely impossible, after source review, checksum verification and staging tests.

## Government-maintained vendor/product status — NCSC-NL (TLP:CLEAR)

An independent, continuously updated **vendor-by-vendor** status list is maintained by the Dutch
government CERT:

- Repo: https://github.com/NCSC-NL/php2shell — **298★ / 101 forks**, created 21 Oct, updated hourly
- Machine-readable layout: `software/software_list_<letter>.md` (31 files), plus
  `software/changelog_software_list.md` (changes), `detection_mitigation/`, `tools/`, `tests/`
- Per product: supplier, product, versions, **status for CVE-2026-109618 / CVE-2026-109619**
  (`Vulnerable` / `Fix` / `Not vuln` / …), and links to the vendor's own advisory
- TLP:CLEAR — safe to redistribute

**Why it matters for us:** it closes the gap our patch matrix cannot cover — **embedded PHP in
commercial appliances**. Every "can't patch this product" question now has an authoritative place to
start. Entries are investigation leads unless backed by a vendor advisory (the repo says so itself).

**Cross-check on PAN-OS:** NCSC-NL lists PAN-OS 12.2/12.1/11.2/11.1/10.2 and Panorama as
**Vulnerable, fixed releases not yet announced** — independently consistent with our
`PAN-OS-EXPOSURE.md` assessment (fixes pending, ETAs 27–30 Oct).

**Usage:** filter by your product inventory; for each hit follow the vendor link for the fix version.
Do not treat "Not vuln" as a permanent state — the list is updated daily and vendors revise.

### ✅ RESOLVED 2026-10-27 — 10.2 branch documentation confirmed by advisory

The advisory was updated on **27 Oct** and now lists `10.2.13-h27` and `10.2.16-h12` as released (their
ETAs were removed). The earlier note below records what the docs-first state looked like; it is history now.

The per-release **"Addressed Issues" pages for `10.2.13-h27` and `10.2.16-h12` are published** and both
state: *"The PAN-OS 10.2.13-h27 / 10.2.16-h12 release includes a fix to address CVE-2026-109618."*
The **advisory had not yet flipped them to released**: it still showed `ETA: 10/27` and `ETA: 10/28`.

Read this the right way:
- **Documentation is not a download.** Check the support portal / software updates page for availability
  in your account before scheduling.
- **Do not treat the advisory ETA as "unavailable"** if your portal offers the build. Palo Alto's
  release notes normally go live with the release; the advisory update can lag by hours.
- The monitor now HEAD-checks every pending build's release-notes page
  (`pan.rn_pending_documented`), so documentation publication is detected as its own signal.
