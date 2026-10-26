# BUILD INFO — php2shell detection & response package

**Build timestamp:** 2026-10-26 00:56 UTC
**Package name:** `php2shell-detection-package-2026-10-24`
**Why the name changed:** the package was first assembled on 2026-10-21 and then materially
updated through 2026-10-22 (tested exploit results, corrected findings, repaired Suricata
ruleset). The folder is now named for the **content date**, not the original assembly date.

> ⚠️ **Supersedes** `php2shell-detection-package-2026-10-21.zip`. If you hold a copy with
> that name, replace it — that build contained a Suricata ruleset that **failed to load**
> (see `02-detections/DEPLOY-NOTES.md`), so it produced **no alerts** while appearing healthy.

## Verify you have the current build

```sh
sha256sum php2shell-detection-package-2026-10-22.zip
# compare against the .sha256 file distributed alongside the zip
```

The zip's own hash cannot be embedded inside itself, so it ships as a sidecar
`php2shell-detection-package-2026-10-22.zip.sha256`.

## What changed on 2026-10-22

1. **Suricata ruleset repaired** — 4 defects (invalid `flowint ... set` syntax, PCRE2
   quantifiers >65535, invalid `less_than` keyword, unescaped `;` in a pcre class) meant the
   whole file failed to load. Now validated: `suricata -T` exit 0, 0 errors, 16 rules.
2. **Zeek / YARA / ModSecurity** re-validated (Zeek 9.0.0 parses; YARA 4.5.5 compiles;
   Apache mod_security2 `configtest` Syntax OK).
3. **Public exploit results are now TESTED, not quoted:**
   - ✅ RCE **confirmed** for `display_errors=On` (4 HTTP requests, `uid=33(www-data)`).
   - ❌ `display_errors=Off` RCE **not reproduced** — earlier claim corrected.
   - Detection validated: a 4,096-byte `PHPSESSID` cookie was observed exactly as our rule
     targets, even while both public exploits failed to complete.
4. **Scope clarification:** PHP **7.4 / 8.0 / 8.1 are affected** despite the CVE titles
   saying "8.2–8.5" — they have no official release, only LTS backports.
5. **New detection rules:** NUL byte in `PHPSESSID` (an arm-stage marker published with the
   public exploit).

## What changed in the 2026-10-22 afternoon rebuild

6. **In-the-wild exploitation confirmed.** Amazon Threat Intelligence reports the first
   PHP2Shell exploitation attempt on **2026-10-17**, four days before disclosure, from
   anonymised infrastructure, with multiple actors active pre-release; AWS describes the
   flaws as "broadly exploited in the wild." START-HERE now instructs hunting **back to
   17 October**, and flags a KEV listing as likely imminent.
   Source: AWS Security Blog (MadPot), corroborated by BleepingComputer.

## What changed in the 2026-10-22 evening rebuild (SOC triage)

7. **Added `06-soc-triage/`** — a four-document SOC module written for analysts who have not
   read the dossier: severity ladder, per-alert triage with first-three-checks and escalation
   criteria, false-positive tuning/baselining guidance, and an incident-response runbook
   (including rotating credentials after a disclosure event, and scoping from **17 Oct**).
   No detection content changed.

## What changed in the 2026-10-23 rebuild

8. **Ubuntu patch path documented.** USN-8948-1 / USN-8948-2 fix both CVEs; verified versions
   for noble/jammy/focal/bionic/xenial/trusty (ESM). Added to START-HERE with a version table.
9. **Monitor defect fixed:** the hourly watch was blind to Ubuntu (assumed a list-shaped API
   that had changed, and only scanned the last 40 notices so the PHP USNs had scrolled out).
   Now uses the per-CVE API and reports USN ids + per-release fixed versions.
   **Ubuntu status was therefore missing from the first ~36 h of reporting** — corrected here.
10. **Package renamed to the content date** (2026-10-23) per convention, since content changed
    and the UTC day rolled.

## What changed in the 2026-10-23 07:45 rebuild

11. **Added `CLARIFICATION-second-vulnerability-claim.md`** — the "second unpatched PHP bug"
    claim is **refuted by the PHP security team** (direct quote, dated, sourced). Includes a
    paste-ready reply for stakeholders.
12. **Added `PATCH-AVAILABILITY.md`** — verified fixed-version matrix by ecosystem (upstream,
    EOL backports, Ubuntu incl. ESM, Debian, Docker images, RHEL/Remi caveat) plus
    verification commands and the "app patching doesn't help / restart required" traps.
13. **Debian 12 bookworm is NOW FIXED** — `8.2.35-1~deb12u1`, **DLA-4848-1**; Debian 13
    `8.4.27-1~deb13u1`, **DSA-6574-1**. (bookworm was still vulnerable on 21-22 Oct.)
14. START-HERE now answers both questions in a block above "What's in this package".

## What changed in the 2026-10-23 11:00 rebuild

15. **NEW: CVE-2026-115560** — PHP published an *informational advisory* (23 Oct, session upload
    progress). **No patch yet** (next regular release). Narrow conditions: app sets
    `session.serialize_handler` to `php_binary`/`php_serialize` then switches to `php` at runtime,
    with upload progress enabled. PHP calls it an *"unlikely RCE vector"*. **Mitigation is
    `session.upload_progress.enabled=0` — already step 1 of our containment order, and already
    published in the 21 Oct advisory.** This is **not** a bypass of the critical fixes.
16. `CLARIFICATION-second-vulnerability-claim.md` updated with a new **§6** so it cannot be accused
    of over-claiming: the "patch is broken" claim remains false, but there is now one real, narrow,
    already-mitigated caveat. Also added to `PATCH-AVAILABILITY.md` (§8b) and START-HERE.
17. Dossier §28 records the advisory, exact conditions, and the probable link to the original
    social-media noise (inference, marked as such).

## What changed in the 2026-10-23 18:45 rebuild (IMPORTANT)

18. **🚨 Palo Alto PAN-OS / Panorama confirmed affected** — no special configuration required,
    **fixes not yet released** (ETAs 26–30 Oct). Added a prominent alert block to START-HERE, a
    full section to `PATCH-AVAILABILITY.md` (§7b: pending versions per branch + interim
    mitigations), dossier §29, and **SOC triage A11** for appliance management planes.
19. **Industrial knock-on:** Siemens **SSA-566512** — RUGGEDCOM APE1808 hosting PAN-OS affected;
    contact Siemens support. Cortex XCORE (21 Oct) and WildFire Cloud (22 Oct) already patched.
20. **Threat numbers moved:** EPSS 109618 **5.31% → 11.62%** (96th pct); EPSS 109619 5.76% → 5.99%.
    NVD both `Analyzed` (refs 5 / 14, incl. Siemens + new oss-security posts). **KEV catalog
    1,754 → 1,755** but the addition is **CVE-2026-114625 (Arista VeloCloud)** — php2shell is
    **still not listed**. PoC repos 786 → **835 (+49)**, the largest hourly jump since disclosure.
21. Unit 42 states it has **seen PoC** and notes a European government took its website offline.

## What changed in the 2026-10-23 19:00 rebuild

22. Added a **citable community reference** to `CLARIFICATION-second-vulnerability-claim.md`:
    Alexandre Daubois' independent analysis of the PHP2Shell rumours (21 Oct), with the useful
    precision that `session.upload_progress.enabled=0` addresses the **session/upload-progress
    arm (109619) only** — it is **not** a mitigation for the OOM arm (109618). Our own wording was
    checked against this and is consistent ("breaks the upload-progress arm").

## What changed in the 2026-10-23 20:15 rebuild

23. **Added `PAN-OS-EXPOSURE.md`** — answers "how many are exposed / would the exploit actually work"
    with published figures, the **exploit-capability reality** (public PoCs do not bypass ASLR on
    x86-64; VulnCheck holds a private working exploit), PAN's **availability-only** assessment
    (`VC:N/VI:N/VA:H`), estate-check commands, and the interim-control priority order.
24. **PAN scope refinements (23 Oct advisory revision):** **WildFire WF-500 / WF-500-B** added as
    affected; mgmt plane = **HTTPS web UI + XML API**, plus dataplane interfaces with a management
    profile; GlobalProtect portal/gateway **not** in scope; **Panorama and WF-500 have no fix date**.
25. START-HERE and `PATCH-AVAILABILITY.md` §7b updated to match.

## What changed in the 2026-10-23 20:30 rebuild

26. **Added `INCIDENT-STATUS.md`** — answers "has any company said it was a victim?". Position:
    **no publicly confirmed compromise**. Includes the **Sophos retraction** (they reported one
    successful exploitation, then corrected it), the French government / Orange precautionary
    outages, the 18.8% of monitored sites pulled offline, attacker tooling evidence (~10 workspaces,
    none with a shell), and — importantly — **why absence of victims is not evidence of safety**
    (silent memory-disclosure path, pre-disclosure attempt on 17 Oct, disclosure lag).
27. Dossier §30 mirrors it. Package rebuilt.

## What changed in the 2026-10-23 21:30 rebuild (capability update)

28. **`display_errors=Off` RCE is now CONFIRMED achievable** — by two independent teams with private
    exploits: **VulnCheck** (x86-64, ASLR on, PHP 8.4.26) and **CovertSwarm** (AArch64, PHP 8.5.11,
    plus one WordPress lab; their 8.5.12 controls did not execute). Neither tool is public.
29. **Our earlier "display_errors=Off unverified" status was too comfortable and is corrected** in
    START-HERE and dossier §31: do not treat `display_errors=Off` as a security control.
30. **Hands-on test of the public claim (9bie repo, 1,218★): NOT REPRODUCED — 14/14 attempts failed**
    against the exact stock image (`display_errors=Off`, prefork 150), at the leak stage. Binary hash
    matches their offsets registry exactly (`51663cf8…`), so it is not a wrong-build artefact; an
    independent researcher also failed to port their parameters to the official image.

## What changed in the 2026-10-24 00:00 rebuild

31. **PAN-OS signature coverage expanded ~5×** (advisory revision 24 Oct: "Threat ID released and
    details updated"): from 5 IDs to **25** — `543004`, `97622`–`97625`, `97643`, `97647`, `97649`,
    `97652`, `97653`, `97656`–`97659`, `97662`–`97664`, `97670`–`97674`, `97676`–`97678`, content
    **9162/9163/9164+**. START-HERE, `PATCH-AVAILABILITY.md` §7b and SOC triage **A11** updated —
    estates that enabled only the original five are under-covered and need content ≥9164.
32. Still **no PAN-OS fixes** (20 ETA markers intact, 26–30 Oct); Panorama / WF-500 undated.
33. Dossier §32. Package **renamed to 2026-10-24** (content changed + UTC day rolled).

## What changed in the 2026-10-24 08:00 rebuild

34. **First credible PUBLIC PHP-FPM chain documented** — `VABISMO/php2shell-nginx-fpm-full-rce`
    (nginx + FPM, CVE-2026-109619, ASLR bypassed via HTTP stale-string leak, **no `display_errors`
    dependency**, verified `uid=` output, per-version profiles, CI/live-FPM workflows). It is
    **conditional**: requires two pools with *different* memory limits (consumer low enough to OOM on
    a ~4 MB session), shared session dir, single-worker/pinned workers, and an app calling
    `session_start()`. Not a stock-host tool.
35. Added detection value from it — **FPM worker deaths / 502 bursts paired with large multipart
    bodies**; the existing YARA `Oversized_Session_File` rule covers the planted 4 MB session artefact;
    `session.upload_progress.enabled=0`, `pm.max_requests` recycling and per-pool memory parity break
    the preconditions. Dossier §33, INCIDENT-STATUS §4b.

## What changed in the 2026-10-24 14:00 rebuild

36. **Published a live status page** — <https://f4n6.co.uk/php2shell/> — generated from the same
    hourly monitoring, so public claims and this package share one source of truth. Updates are
    published automatically when the underlying facts change.
37. This package is the **downloadable companion** to that page: full dossier, detection rules,
    hunting queries, SOC triage, patch matrix and PAN-OS exposure notes. No exploit code.

## What changed in the 2026-10-24 16:00 rebuild

38. **Triaged a major public exploit framework** — `JoasASantos/php2shell-exploit` (163★). Built and
    ran its own Docker lab unchanged and used its own offsets: **v1 and v2 both fail at the leak
    stage on x86_64**, despite its amd64 profile being labelled "verified 20/20". Its recorded demo
    successes are on **arm64**. Added to the capability assessment in `INCIDENT-STATUS.md`.
39. No change to detections. The framework uses the same primitives, so existing rules and the
    `session.upload_progress.enabled=0` mitigation remain the correct response.

## What changed in the 2026-10-24 17:00 rebuild — CAPABILITY CONFIRMED

40. **A public pre-auth RCE was reproduced with `display_errors=Off`.** Running
    `JoasASantos/php2shell-exploit` against its own stock lab (`php.ini-production`,
    display_errors Off) achieved `uid=33(www-data)` on **x86_64 and arm64** — **when Apache prefork
    runs a single worker**. Multi-worker pools failed at the leak stage on both architectures.
    Verified independently of the tool's output (command wrote a file read back via `docker exec`).
41. **What this does and does not mean:** the "public PoC cannot do display_errors=Off" assumption is
    now **false**. But this is not a universal switch: it requires mod_php + prefork + single worker +
    `session.upload_progress` enabled. FPM deployments are unaffected by this tool.
42. **New detection content for this tool's artefacts:** Suricata rules for `*.p2s.php` URI access and
    the webshell's distinctive body, a YARA rule for the 105-byte webshell, and hunting queries for
    `.p2s.php` / `.p2s_v2.php` / `.htaccess` writes. See dossier §35.

## What changed in the 2026-10-24 18:00 rebuild

43. **Documented the two real upstream bugs behind the "second vulnerability" noise** (verified on the
    php-src tracker): #24481, an *open* `unserialize()` UAF with no CVE that is **not** a bypass; and
    #24488, a **regression introduced by 8.4.27 / 8.5.12** that double-frees SimpleXML state and
    crashes workers. Patch guidance now includes staging the rollout and recognising the crash.
44. **Added a caveated note on community mitigation:** a third-party native extension
    (`hp_uploadprogress_guard`) that protects unpatched PHP — useful where patching is impossible,
    but a native extension is a supply-chain risk and never a substitute for the official builds.

## What changed in the 2026-10-25 06:00 rebuild

45. **Verified a WAF content-type bypass** (from `dinosn/php-cve-2026-10961x-lab-poc` research):
    PHP accepts `Content-Type: multipart/form-data, boundary=X` (comma instead of semicolon) and
    parses the multipart body normally. Reproduced on `php:8.4.26-apache`. Signatures anchored on
    `multipart/form-data;` miss it.
46. **Our rules already survive it** — they match the substring without requiring the semicolon; the
    ModSecurity rule anchors on `^multipart/form-data`. Documented so SOC teams do not "harden" the
    rules into being bypassable.
47. PAN-OS advisory revised 25 Oct: FAQ updates plus additional Prisma product rows (all unaffected);
    Threat Prevention IDs unchanged at 25; fixes still pending, ETAs 27–30 Oct.

## What changed in the 2026-10-25 15:00 rebuild — EPSS ESCALATION

48. **EPSS jumped to near-certain exploitation.** FIRST's 25 Oct daily update: CVE-2026-109618
    **0.99981**, CVE-2026-109619 **0.99997** (from 11.8% / 6.2%). Verified against the official
    daily datasets across 23–25 Oct: same model version, control CVEs unchanged → a real
    exploitation-evidence surge, not a re-scoring artefact. KEV still NO (1,756).
49. Interpretation and caveats in `INCIDENT-STATUS.md` and dossier §38: very high exploitation
    intensity, but the remediation is unchanged — patch, disable upload progress, restrict PAN-OS
    management exposure, and treat oversized-`PHPSESSID` observations as likely hostile.

## What changed in the 2026-10-25 18:55 rebuild — CYFIRMA campaign IoCs

50. **Ingested CYFIRMA's IoC set** (advisory v3): 15 staging + 1 variant, 17 suspected source IPs,
    dropper host/URL, 4 scanner user-agents, boundary prefix, `JACKALPOC` canary, SHA-256 + MD5 of the
    179,632-byte ELF second stage, plus behavioural indicators. Defanged, with provenance and the
    vendor's own "investigate before blocking" caveat — see `04-hunting/cyfirma-iocs-2026-10-25.md`.
51. **Three new Suricata rules** derived from it (SIDs 2202610118/119/120), validated with
    Suricata 8.0.7 `-T` (exit 0). Rule count 18 → 21. The canary rule is the valuable one: a
    `JACKALPOC` string in a response means blind-RCE validation succeeded.
52. Attribution reminder: CYFIRMA assesses **moderate confidence** for the suspected DPRK/Lazarus link.
    Report it as *suspected*, and remember some quoted scanner user-agents also belong to defensive
    scanning (Amazon/VulnCheck) — correlate with request shape.

## What changed in the 2026-10-25 23:59 rebuild — THN update triaged

53. **THN article updated but NOT corrected.** The flagged article changed by two section headings; the
    Unit 42 paragraph it is built on was **retracted by Unit 42 on 25 Oct** and the article carries no
    correction notice. Our documents carry the corrected position (dossier §39.6).
54. **New artefact: `p2s-rider`.** Defused Cyber reports PHP2Shell probes against **PAN-OS GlobalProtect
    honeypots** from `204.76.203[.]7`, carrying a `PHP_SESSION_UPLOAD_PROGRESS` marker `p2s-rider` and a
    dummy file upload. Added Suricata **SID 2202610121** (rule count 21 → 22) and recorded it in
    `04-hunting/cyfirma-iocs-2026-10-25.md` (Addendum). First artefact specifically indicating
    **appliance** targeting rather than generic PHP estate scanning.
55. **ReliaQuest detection sequence** added to hunting doc: POST → 500 → PHP memory-exhaustion/heap-corruption
    → Apache worker crash. Corroborates our reproduction signature.
56. Scale caveat recorded: Xpanse 22.6M **potentially vulnerable** vs Bitsight ~37M **PHP systems overall** —
    different denominators, do not conflate.

## What changed in the 2026-10-26 01:00 rebuild — false-positive correction

57. **Corrected a false positive in our own reporting.** The tracked THN article was reported as "updated
    but not corrected" at 25 Oct 23:55 UTC. Re-verified with a **normalised text diff** across three
    captures (18:50, 23:55, 00:55): **byte-identical** — the article never changed; the byte delta came
    from the reader proxy used to reach the Cloudflare-protected page. Dossier §40 rewritten.
58. **Method fix:** for reader-proxied pages, strip links/images/URLs and compare normalised text; never
    trust raw sizes or hashes for that source. Note added to the monitor config.
59. **Position unchanged:** that article still carries the Unit 42 claim Unit 42 retracted on 25 Oct, with
    no correction notice. Victim status remains "no publicly confirmed victim tied to these two CVEs".
60. **Kept:** the `p2s-rider` artefact and its detection (SID 2202610121) — it was in the article from
    first publication; we simply extracted it later.

## What changed in the 2026-10-26 03:00 rebuild — NCSC-NL vendor status

61. **Added NCSC-NL's government-maintained vendor/product status list** as the authoritative reference
    for embedded-PHP products (`PATCH-AVAILABILITY.md`, new section). TLP:CLEAR, updated hourly, 31
    per-letter files plus a changelog; includes Palo Alto Networks PAN-OS/Panorama listed **Vulnerable,
    fixed releases not yet announced** — independently consistent with our PAN-OS assessment.
62. Monitor now tracks the NCSC-NL README (vendor-status activity signal).

## Reading order

| File | Why |
|---|---|
| `START-HERE.md` | The one-pager: what to do, in order |
| `01-threat-intel/php2shell-threat-intel-dossier.md` | Full dossier incl. §21 hands-on verification |
| `02-detections/DEPLOY-NOTES.md` | **Suricata compatibility fixes — read before deploying** |
| `03-hardening/` | Config mitigations |
| `04-hunting/` | 29 hunting queries |
| `05-validation/` | Lab validation evidence |
| `06-soc-triage/` | **SOC alert triage, FP tuning, incident response** |
| `CLARIFICATION-second-vulnerability-claim.md` | **Is there a second bug? Answered from primary sources** |
| `PATCH-AVAILABILITY.md` | **Verified patch matrix by distro and ecosystem** |
| `PAN-OS-EXPOSURE.md` | **PAN-OS: exposure numbers, exploit reality, estate checks** |

## Honest limitations

- Detection rules are validated as **loadable and syntactically correct**; they have not all
  been tuned against production traffic volumes. Expect false positives on
  `session.upload_progress`-heavy applications.
- The `display_errors=Off` RCE claim from public research is **unverified** by us.
- No KEV addition as of this build; the two CVEs remain NVD status `Modified`.
