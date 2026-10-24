# PATCH AVAILABILITY — php2shell (CVE-2026-109618 / CVE-2026-109619)

**Verified from primary sources on 2026-10-23.** This is the "are we actually patched?" page.

> ⚠️ **Two rules before the tables:**
> 1. **"Patched" = fixed package installed **AND** PHP workers restarted.** Stale worker state
>    survives a package upgrade; an upgraded-but-not-restarted host is **still exploitable**.
> 2. **Patching the application does nothing.** This is a bug in **PHP itself**. WordPress,
>    Drupal, Laravel, Magento, cPanel and plugin updates do **not** fix it — the PHP runtime
>    must be updated.

---

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

## 7b. ⚠️ Palo Alto Networks PAN-OS / Panorama — affected, fixes PENDING

PAN-OS and Panorama are **affected** by both CVEs, with **no special configuration required**.
**Fixed versions are not released yet** — ETAs **26–30 Oct 2026**. PAN rates its own product impact
**CVSS-B 8.7 HIGH** (suggested urgency: MODERATE).

| Branch | Fixed (pending) | ETA |
|---|---|---|
| 12.2 | `12.2.4-h1` | 10/28 |
| 12.1 | `12.1.7-h11` / `12.1.4-h13` / `12.1.10-h3` | 10/28 – 10/30 |
| 11.2 | `11.2.10-h16` / `11.2.13-h4` / `11.2.16-h1` / `11.2.7-h23` / `11.2.4-h23` | 10/26 – 10/30 |
| 11.1 | `11.1.16-h4` … `11.1.7-h12` | 10/26 – 10/30 |
| 10.2 | `10.2.13-h27` / `10.2.16-h12` / `10.2.10-h42` / `10.2.7-h39` | 10/27 – 10/30 |

**Interim mitigations (until PAN-OS fixes ship):**
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

**Also affected (23 Oct revision):** **WildFire appliances WF-500 / WF-500-B** (all versions) and
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
