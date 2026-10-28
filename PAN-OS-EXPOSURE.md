# PAN-OS exposure, exploitability and the patch window (25–30 Oct) — **patches now shipping**

**Prepared 2026-10-23.** For network/security teams who own Palo Alto estates. This answers three
questions: *how many are exposed*, *would an exploit actually work*, and *what do we do before the
fixes land*.

---

## 0. UPDATE 2026-10-26 — hotfixes have started shipping

Palo Alto's advisory timeline records releases: **25 Oct** — `10.2.18-h13`, `11.1.16-h4`, `11.2.10-h16`;
**27 Oct** — `10.2.13-h27`, `10.2.16-h12`;
**26 Oct** — `11.1.4-h38`, `11.1.6-h40`, `11.1.10-h36`, `11.1.13-h16`. Release notes for those builds
state they "include a fix to address CVE-2026-109618". Thirteen further builds remain on ETA 27–30 Oct
(12.2 / 12.1 / most of 11.2 / 11.1.7 / most of 10.2). **Panorama follows the same hotfix table**
date.** Treat internet-reachable management interfaces as exposed until the relevant build is installed.

## 1. How many PAN-OS management interfaces are on the internet?

**There is no CVE-specific public count yet for this campaign.** What exists are baselines and
proxies — treat all of them as estimates, not inventories:

| Source | Figure | What it measures |
|---|---|---|
| **Shadowserver** (Nov 2024) | ~**11,000** exposed PAN-OS management interfaces globally (~4,000 US), dropping to ~**2,700** after a public cleanup push | Internet-exposed mgmt interfaces |
| Shadowserver (May 2026) | ~**5,800** PAN-OS VM-Series with direct internet exposure (Asia 2,466 / N. America 1,998) | VM-Series specifically |
| Wiz (May 2026) | **7% of cloud environments** had a publicly exposed PAN-OS instance | Cloud estates |
| Palo Alto Networks' own claim | **<0.5%** of its firewalls have an internet-exposed management interface | Vendor assertion |
| **Cortex Xpanse** (Unit 42, 21 Oct 2026) | **22.6 million** exposed instances potentially vulnerable — **this is PHP-wide, not PAN-OS** | All internet PHP services |

**Bottom line:** the honest answer is *low thousands to ~10,000 PAN-OS management planes are
internet-reachable at any given time*, but **no one has published a current, CVE-specific count**.
Anyone quoting a precise PAN-OS number for this CVE today is guessing.

### How to get a real number
- **Your own estate (authoritative):** Panorama device inventory + config audit — see §4.
- **Shadowserver** — free daily exposure reports for network owners and national CERTs. This is the
  source most published counts come from.
- **Censys / Shodan / FOFA** — PAN-OS management UI is identifiable (`http.title:"PAN-OS"`,
  login-page fingerprints). Censys also runs a public PHP2Shell dashboard updated hourly.
- **Cortex Xpanse / your EASM** — if you already own it, it will list your exposed assets.
- Palo Alto has previously tagged customers' internet-exposed devices inside the product support
  portal ("Remediation Required" lists) — check whether that is active for this advisory.

**Do not read an internet-wide count as your risk.** A global number you cannot act on is
situational awareness; your own exposed management planes are the actual problem.

---

## 2. "Can you just run the exploit and get RCE on these firewalls?"

**Not with public tooling today — but a working private exploit does exist.** Both halves matter.

### The exploit-capability reality (VulnCheck, 22 Oct)
- **Public PoCs: "none of those bypass ASLR on x86-64 systems on their own."** PA-Series and most
  VM-Series are x86-64, so **the circulating GitHub PoCs are not a turnkey weapon against PAN-OS.**
- **VulnCheck holds a working, non-public exploit** for CVE-2026-109618: it chains a memory leak into
  RCE on **PHP 8.4.26, x86-64, with ASLR enabled and `display_errors` disabled** — i.e. normal
  production config. It is sold to Initial Access Intelligence customers, **not public**.
- On **ARM64** the picture is messier: VulnCheck says the memory leak works but the RCE step does
  not; other reporting says ARM64 ASLR is brute-forceable relatively easily. **Treat ARM-based
  VM-Series as a lower bar for a determined attacker.**
- Expect **mass scanning and crash attempts regardless** — most will fail, and a flood of requests
  in logs will say little about real risk.

### What Palo Alto says the impact on PAN-OS is — read the vector
PAN scores this **CVSS-B 8.7** for its own products, *lower than the 9.2 PHP assigned*, and the
vector explains why:

> `CVSS:4.0/.../VC:N/VI:N/VA:H/...` — **Confidentiality: None, Integrity: None, Availability: High**

**Palo Alto assesses the impact on PAN-OS as an outage, not as data compromise or code execution.**
PAN also states it is **not aware of malicious exploitation against its products**, and lower its
rating to **7.1** if management access is restricted to a single jump box.

So the calibrated risk is:
| Scenario | Likelihood | Impact |
|---|---|---|
| Mass scanning / failed exploit attempts | **High, already happening** | Noise, possible crashes |
| **DoS** — firewall reboot/crash from crafted requests | **Plausible** (PAN's own vector) | Outage on a perimeter device — serious but recoverable |
| **Targeted RCE** using a private exploit (VulnCheck-class) against an internet-exposed mgmt interface | **Low volume, high impact** | Full device compromise — the scenario to prevent |
| Mass RCE with public PoCs on x86-64 | **Low** (no public ASLR bypass) | — |

**"A bad few days" is a reasonable instinct, with a correction:** expect lots of attempts and some
crash-based outages; expect targeted RCE only from actors who already have a working exploit. The
defensive priority is the same either way: **get the management plane off the internet.**

---

## 3. What exactly is in scope on PAN-OS

Per Palo Alto's advisory (revised 23 Oct):
- **Affected:** PAN-OS 10.2 / 11.1 / 11.2 / 12.1 / 12.2 (all builds), **Panorama** (all versions),
  and **WildFire appliances WF-500 / WF-500-B**, which were briefly listed as affected in the 23 Oct
  revision and then **corrected to not affected** (vendor table: `None` affected / `All` unaffected)
- **In scope on the device:** the **management web interface** = the **HTTPS web UI *and* the XML API
  service**, plus **any dataplane interface that has a management profile attached**
- **Not in scope:** GlobalProtect portal and gateway, the captive portal
- **Not affected:** Cloud NGFW, Prisma Access/Cloud, GlobalProtect App, Cortex XDR/XSIAM/XSOAR/Xpanse,
  Bridgecrew, Strata Cloud Manager, Idira, Cortex XDR Broker VM
- **Already remediated:** Cortex XCORE (21 Oct), WildFire Cloud (22 Oct)

**Timeline:** first hotfixes **26 Oct** (`10.2.18-h13`, `11.1.16-h4`, `11.2.10-h16`); `10.2.13-h27` and
`10.2.16-h12` released **27 Oct**; rest by
**30 Oct**. ⚠️ **Panorama uses the same releases** — upgrade it to the same hotfix as its train; until then run restricted
indefinitely for those.

---

## 4. Check your own estate (copy-paste)

```sh
# --- From Panorama: inventory every managed firewall + version ---
# GUI: Panorama > Managed Devices > Summary   (fastest visual check)
# API:
curl -k -s "https://<panorama>/api/?type=op&cmd=<show><devices><all></all></devices></show>&key=<APIKEY>"

# --- On each firewall: version, mgmt IP, permitted management sources ---
show system info                     # confirm PAN-OS version against the affected list
show interface management            # mgmt interface config + IP
show deviceconfig system permitted-ip   # who is allowed to reach mgmt (empty = everyone)

# --- Which dataplane interfaces carry a management profile? (in scope per advisory) ---
show running config | match "management-profile" context 2
# any dataplane (ethernet1/1, ae1 ...) with a management profile is reachable for mgmt purposes
```

```sh
# --- From OUTSIDE: is the management plane actually reachable? (probe your own IPs only) ---
for p in 443 4443 3879; do
  echo -n "port $p: "
  curl -k -sS -o /dev/null -m 6 -w '%{http_code}\n' "https://<MGMT-IP>:$p/" 2>/dev/null || echo unreachable
done
# A 200/302/403 means something answered on the management plane = exposed.
# 4443/3879 matter because Unit 42 found GlobalProtect profiles mis-mapped onto the
# management interface, silently exposing it on those ports during the Lunar Peak campaign.
```

**Also check Panorama** — in scope, fixed by the same PAN-OS maintenance releases. **WF-500 / WF-500-B are not affected** (vendor correction).

---

## 5. Interim controls, in priority order

1. **Remove internet reachability of the management plane.** Trusted internal sources only, or a
   single jump host. This is the control that lowers PAN's own severity from 8.7 to 7.1, and it is
   the only one that works regardless of exploit capability.
2. **Review dataplane interfaces carrying management profiles** and remove them where the interface
   faces an untrusted network.
3. **Threat Prevention** IDs **543004, 97622, 97623, 97624, 97625** (content **9162+**) — but they
   only protect the management plane if MGT traffic is routed through a DP port, the inbound
   management certificate is replaced, **inbound management traffic is decrypted**, and threat
   prevention is enabled on management services. Without that chain the signatures do not see it.
4. **Hunt for crash/reboot events** that correlate with inbound management requests — with PAN's
   availability-only assessment, an unexplained firewall restart is a more likely sign of an attempt
   than a compromised configuration.
5. **Patch on release:** 26–30 Oct per branch; Panorama uses the same hotfixes. WF-500 not affected.

---

## 6. What is *not* known (so nobody over-claims)

- No public count of internet-exposed PAN-OS management planes **for this CVE**.
- No public PAN-OS exploit, and no confirmed exploitation of PAN-OS itself.
- Palo Alto has not explained how it concluded availability-only impact, and its assessment assumes
  the PHP layer on PAN-OS is not exploitable to code execution in the realised configuration.
- Whether a private exploit works against PAN-OS `x86-64` with its hardening is **unverified**.

**Working assumption for defenders:** plan for outages as the realistic near-term impact, and for
targeted RCE as the severe-but-lower-likelihood case. Both are resolved by the same control —
take the management plane off the internet.

**Sources:** PAN advisory CVE-2026-109618 (updated 2026-10-23) · Unit 42 threat brief (21 Oct) ·
VulnCheck analysis via Censys / Help Net Security (22 Oct) · Shadowserver figures via BleepingComputer,
SecurityWeek, TechTarget (2024–2026) · Wiz (May 2026) · heise/Censys (23 Oct) · OX Security (22 Oct).

## Release-notes ahead of advisory (2026-10-26)

**Resolved 27 Oct:** the advisory now lists `10.2.13-h27` and `10.2.16-h12` as released. The note below is
kept as the record of the docs-first window. Both have "Addressed Issues" pages stating they include the fix
for CVE-2026-109618, while the advisory still showed ETAs of 10/27 and 10/28 at 23:59 UTC. These are the
**only** two pending builds with documentation live. Check the support portal for actual availability;
the advisory can lag the release. The monitor now tracks this via `pan.rn_pending_documented`.
