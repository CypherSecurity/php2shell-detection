# Has anyone actually been compromised? — php2shell incident status

**As of 2026-10-23 20:00 UTC: no organisation has publicly confirmed a successful compromise from
CVE-2026-109618 / CVE-2026-109619.** There is heavy attempted exploitation, one retracted victim
report, and significant self-inflicted disruption. That is not the same as "nobody was hit" — see §5.

---

## 1. The confirmed position

| Claim | Status | Source |
|---|---|---|
| Attempts in the wild | **Yes, millions** | Cloudflare; Wordfence (74k+ blocked); AWS MadPot |
| Attempts predating disclosure | **Yes — 17 Oct** | AWS Threat Intelligence |
| **Confirmed successful compromise** | **None publicly confirmed** | Wordfence (22 Oct); Hunt.io; Flawfence (23 Oct) |
| Retracted victim report | **Sophos — retracted** | Sophos advisory update |
| CISA KEV listing | **No** (checked 08:00 UTC 23 Oct) | CISA |
| Vendor product compromise (PAN-OS) | **None reported**; PAN says unaware of exploitation against its products | Palo Alto advisory |

## 2. The one "victim" claim — and its retraction

**Sophos** initially reported *"one successful exploitation"* in customer environments and a payload
written to `/tmp/nfs` executed as `./nfs php` (a Mirai variant dubbed "Potassium", User-Agent
referencing php2shell, C2 `134.199.154.64`).

On further analysis **Sophos corrected that assessment**:

> *"Sophos customer telemetry shows scanning and a small number of failed exploitation attempts. As of
> this update, there is no evidence of a successful compromise due to these vulnerabilities."*
> — and the payload *"was not delivered since the exploitation attempt was unsuccessful due to being
> blocked by Sophos countermeasures."*

**This is the closest thing to a victim report in the public record, and it was withdrawn.** Treat
anyone citing "Sophos confirmed a compromise" as out of date — Sophos themselves withdrew it.

## 3. What *did* happen: disruption, not compromise

- **France:** the tax authority's site, several prefectures and the family benefits agency showed
  maintenance pages; Météo-France and the Ameli home page went down and came back. **CERT-FR**
  issued alert **CERTFR-2026-ALE-014** (updated 22 Oct to flag PoC availability).
- **Orange** took sites and apps of several subsidiaries offline **as a precaution**.
- **Oh Dear** uptime monitoring recorded **18.8% of monitored sites offline at the peak**, versus 0.9%
  the week before — operators pulling their own sites down rather than wait to be hit.

**All of this is precautionary self-harm, not evidence of compromise.** It is also a reminder that
the operational damage from a panic can exceed the damage from a failed exploit.

## 4. What the attackers actually achieved (per researchers observing them)

| Observation | Detail |
|---|---|
| Actor infrastructure | Mirai-style IoT botnet active since ≥ May 2026 bolted php2shell onto its spreading kit (scanner `45.198.224[.]169`, UA `php2shell-109618`) |
| Mass-exploitation attempt | One operator ran **10 passes against up to 123 servers** via proxy network — **zero shells** |
| Attacker workspaces | ~10 observed holding php2shell tooling — **none held a victim list, shell or stolen data** |
| Code-review consensus | VulnCheck, watchTowr, Rapid7, Sansec, Sophos, Hunt.io agree: **no public PoC clears ASLR on x86-64**; most crash on a default install |
| WordPress estate | Wordfence: **74,000+ attack requests blocked**, no compromise reported |
| Target preference | Commerce/billing/hosting on old PHP (5.x–8.1), i.e. hosts that will never be patched |

Hunt.io put it precisely: *"Big exposure, clear intent, no confirmed working mass exploit yet."*

## 4b. Capability is maturing (updated 23 Oct) — this is the number to watch

Attempts are failing **publicly**, but the exploit capability behind them is improving:

- **VulnCheck** (22 Oct) built the first known exploit achieving RCE on **x86-64 with ASLR enabled and
  `display_errors=off`** (PHP 8.4.26) — private, sold to customers.
- **CovertSwarm** (23 Oct) independently achieved the same on **AArch64 PHP 8.5.11**, and got code
  execution in one WordPress lab — private, deliberately unreleased. Their **8.5.12 controls did not
  execute**.
- A public repo claiming the same (`9bie/php2shell-bypass-aslr-exp`, 1,218★) is **unverified**: we
  tested it 14 times against the exact stock image and it failed at the leak stage, and another
  researcher independently failed with the earlier iteration.

- **A public PHP-FPM chain appeared 24 Oct** (`VABISMO/php2shell-nginx-fpm-full-rce`): nginx + FPM,
  CVE-2026-109619, **ASLR bypassed over HTTP, no `display_errors` needed**, verified output shown.
  It is **conditional**, not universal — it needs two pools with *different* memory limits (one low
  enough that decoding a ~4 MB session OOMs), a shared session directory, single-worker/pinned
  workers that don't recycle, and an app that calls `session_start()`. A stock single-pool 128M host
  does not match. Treat FPM as publicly tooled for multi-pool/shared-session deployments.

- **Update 24 Oct — PUBLIC WORKING EXPLOIT CONFIRMED (conditional).** The framework
  `JoasASantos/php2shell-exploit` was run against its own lab (PHP 8.4.26, stock
  `php.ini-production`, **`display_errors=Off`**, upload progress On). Result: **pre-auth RCE
  reproduced** on **both x86_64 and arm64** — but **only when Apache prefork runs a single worker**.
  Multi-worker pools failed at the memory-leak stage on both architectures. Proof was taken
  independently of the tool's own output: the command wrote a file inside the target container
  (`uid=33(www-data)`), read back with `docker exec`.
  **What changed:** a public exploit now covers the `display_errors=Off` case that previously
  required private tooling. **What did not:** it is not universal — it needs mod_php + prefork +
  single worker + `session.upload_progress` enabled. FPM deployments are unaffected by this tool.
  Mitigation is unchanged and still effective: patch, and/or `session.upload_progress.enabled=0`.
  Detection: the tool plants `/.p2s.php` (also `/assets/.p2s.php`, `/tmp/.p2s.php`) and v2 uses
  `/tmp/.p2s_v2.php` + `.htaccess`.

- **Update 25 Oct — EPSS moved to near-certain.** FIRST's 25 October daily update put
  CVE-2026-109618 at **0.99981** and CVE-2026-109619 at **0.99997** (from 11.8% / 6.2% the day
  before). Verified against the official daily datasets: same model version, and control CVEs
  (log4j, PAN-OS CVE-2024-3400) unchanged — so this is a **real exploitation-evidence surge**, not a
  re-scoring artefact. KEV remains NO. Interpretation: exploitation intensity is now very high, the
  remediation is unchanged.

**So the public story is "attempts fail"; the private story is "capability exists".** Today's
absence of a confirmed victim is therefore a statement about *exploit availability and intent*, not
about *inherent difficulty*. That gap is exactly what closes when a working public exploit appears.

## 5. Why "no confirmed victims" is not "nobody was hit"

Four reasons to hold both ideas at once:

1. **The disclosure mode is silent.** CVE-2026-109619 lets an attacker read other requests' memory —
   passwords, session tokens, API keys — **and return it in a `PHPSESSID` cookie**. No shell, no
   crash, no child process. A successful theft of this kind looks like nothing in most telemetry.
2. **Compromise may predate the advisory.** AWS observed an exploitation attempt on **17 Oct**, four
   days before disclosure. Anybody compromised on the 17th has had no reason to know.
3. **Disclosure lag is normal.** Organisations typically take weeks to months to confirm and publish a
   breach — and many never publish at all if regulation does not force it.
4. **The exploit is hardest exactly where PoCs are useless.** Actors with a private working exploit
   (VulnCheck-class) have no incentive to announce a victim.

**Practical reading:** the absence of a named victim is evidence that *mass, noisy exploitation has
not succeeded publicly*. It is **not** evidence that targeted, quiet compromise has not occurred.
Treat your own 17–23 October window as potentially exposed and hunt accordingly.

## 6. What would change the picture (watch items)

- First **confirmed** compromise with technical detail (webshell, skimming script, credential theft).
- A **public ASLR-bypassing exploit** for x86-64 — would immediately change mass-exploitation odds.
- **KEV addition** — CISA's confirmation of in-the-wild exploitation.
- Hosting provider reporting successful intrusion rather than blocked attempts.
- Post-incident reports citing php2shell as initial access (ransomware, BEC, card skimming).

## 7. What to say if asked "has anyone been hacked?"

> "No organisation has publicly confirmed compromise from these CVEs. The one reported victim —
> Sophos — was retracted by Sophos themselves after analysis showed failed attempts. There are
> millions of attempts, a French government outage that was precautionary, and no confirmed shell.
> That said, the memory-disclosure path is silent by design, one attempt predates disclosure by four
> days, and breach disclosure lags — so absence of reports is not evidence of safety. Hunt from
> 17 October."

**Sources:** Sophos advisory (updated 22/23 Oct) · Wordfence blog (22 Oct) · Hunt.io research
(Oct 2026) · AWS Security Blog MadPot post (21 Oct) · Flawfence summary (23 Oct) · CERT-FR
CERTFR-2026-ALE-014 · CISA KEV (checked 23 Oct) · Palo Alto advisory (updated 23 Oct) · hosting
provider status pages.
