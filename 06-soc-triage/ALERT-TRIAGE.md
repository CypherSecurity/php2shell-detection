# ALERT TRIAGE — per signal

Each entry: **what fired → what it means → first three checks → escalate if → known
false positives.** Rule IDs are for the shipped rules.

---

## A1 — Oversized or non-alphabet `PHPSESSID` **response** cookie  ·  **P1**

**What it is.** A legitimate PHP session id is **26 characters** from `[A-Za-z0-9,-]` and is
**never percent-encoded**. The public disclosure chain makes PHP emit its own process memory
URL-encoded into the `PHPSESSID` cookie — observed in our lab as a **4,096-byte** cookie
beginning with a long run of `M`/`A` then binary data.

**Why P1.** This is **data theft in progress or completed**. The leaked region can contain
session tokens, credentials, API keys, and other requests' data from the same worker.

**First three checks**
1. Pull the raw response header (proxy/WAF/PCAP, or the access log if it captures cookies).
   Measure length and character set. >32 chars, or any `%` escape, is a hit.
2. Identify the **client IP** and whether it made a preceding multipart `POST` that produced
   an OOM/500 (the producer request).
3. Determine the affected app's **session contents sensitivity** — was the customer logged
   in? What secrets live in `$_SESSION`?

**Escalate immediately if** the cookie is present in a response to an external client.
Treat as a **credential/session compromise**, not a failed attack.

**Known false positives**
- Load balancers / WAFs that re-encode or rewrite `Set-Cookie` values.
- Applications that (incorrectly) put non-session data in `PHPSESSID`.
Baseline one week; genuine hits should be zero.

---

## A2 — NUL byte in `PHPSESSID` request cookie  ·  Suricata **2202610114 / 2202610115** · **P2**

**What it means.** A working public exploit sets `PHPSESSID` to a NUL byte to make PHP mint a
new session id while leaving session state dirty. **No legitimate client sends this.**

**First three checks**
1. Confirm the raw byte is in the `Cookie` header (not a logging artefact).
2. Count how many hosts / customers received it from the same source IP — one IP hitting
   many customers is a campaign, not a false positive.
3. Check that host's PHP version and whether workers restarted since patching.

**Escalate if** the target is unpatched, or the same source hits multiple customers.

**Known false positives**
- Essentially none. Malformed scanners will occasionally emit it — still worth blocking.

---

## A3 — Giant multipart filename (64 KB+, 1 MB+) · Suricata **2202610107 / 2202610108** · **P2**

**What it means.** A `filename="…"` >64 KB is used to force a large allocation and trigger the
OOM at a chosen point. At 1 MB+ this is a **confirmed arm stage** in the published exploit.

**First three checks**
1. Is the request going to a **PHP endpoint** (any `.php`) on a host that serves PHP?
2. Did that host return **500** on the same request, or restart a worker shortly after?
3. Is the client a known internal scanner or a real user agent?

**Escalate if** the host is unpatched, or an armed sequence (A3 → 500 → follow-up POST) appears.

**Known false positives**
- Bulk upload tools with pathological names (rare); some backup agents.

---

## A4 — Arm receipt / fire-stage sequence · Suricata **2202610111 / 2202610112** · **P2**

**What it means.** A 500 response after a giant-filename multipart indicates the worker
**survived a failed startup** — the exact precondition for the stale-state reuse. A second
multipart POST on the same flow is the **fire stage**.

**First three checks**
1. Confirm the 500 correlates to the giant-filename request (same flow/client).
2. Look for a **subsequent request from the same client** within seconds.
3. Check host logs for `Allowed memory size … exhausted … in Unknown on line 0`.

**Escalate if** both produce and fire stages are present → **assume RCE attempt in progress**.

**Known false positives**
- Note: these rules use flow correlation and may under-fire where `Connection: close` breaks
  the flow. **Absence of 0112 does not mean absence of attack** — rely on host logs.

---

## A5 — `Session object destruction failed` at PHP Request Startup · Sigma · **P1**

**What it means.** The **FPM** RCE path (`nzd`-style chain): a stale `BG(unserialize)` context
reached by the upload-progress handler before normal request init. Healthy PHP estates do not
produce this line at Request Startup.

**First three checks**
1. Confirm the log line is at **Request Startup**, not a normal session teardown.
2. Check whether the same worker previously logged an OOM/fatal for a large upload.
3. Determine if the host runs **FPM** (most modern deployments do).

**Escalate if** there is a preceding OOM within minutes, or the host is unpatched.

**Known false positives**
- Genuinely rare. Applications that corrupt session handlers can produce similar wording —
  verify exact string.

---

## A6 — Producer/consumer OOM pair on the same worker · Sigma (correlation) · **P2**

**What it means.** One request OOMs (`Allowed memory size … exhausted … in Unknown on line 0`),
then a **later** request handled by the **same worker pid** shows session/state anomalies.
This is the signature of state that failed to roll back.

**First three checks**
1. Same worker pid for both events, within **60 seconds**?
2. Was the producer a **multipart POST** (and large)?
3. Did the host serve a subsequent anomaly to the **same client IP**?

**Escalate if** producer→consumer pair is confirmed **and** the host is unpatched.

**Known false positives** — **the noisiest family in the package**
- Legitimate large uploads hitting `memory_limit`
- Capacity/memory-pressure incidents
- PHP apps with tight `memory_limit` on batch jobs
→ Always require the *pair* and the *same worker*. A lone OOM line is not an alert.

---

## A7 — Multipart part flood / 100+ parts · Suricata **0102 / 0103 / 0109**, Zeek `Multipart_Part_Flood` · **P3**

**What it means.** Many multipart parts (or header lines) amplify memory consumption. The
published chains require **≥1,902 parts**, well above this rule's threshold, so this is an
early-warning tier.

**First three checks**
1. Part count vs. what the endpoint legitimately accepts.
2. Endpoint type — is it a file-upload form?
3. Any OOM/500 on the same host within minutes?

**Escalate** if the endpoint is not an upload endpoint, or part count is in the thousands.

**Known false positives**
- Bulk uploaders, form builders, ticketing systems with dynamic fields, some CRM imports.

---

## A8 — Chunked / close-delimited multipart with no `Content-Length` · **2202610100 / 2202610101** · **P3**

**What it means.** `post_max_size` is compared against a *declared* length; without one, PHP
may read an unbounded body. Legitimate clients rarely do this.

**First three checks**
1. Client user-agent / known integration?
2. Body size actually observed.
3. Same host's memory/OOM logs.

**Escalate** if combined with A3/A4/A5.

**Known false positives**
- Some legacy HTTP clients and streaming upload libraries.

---

## A9 — Multipart body on a non-POST method · **2202610106** · **P3**

**What it means.** PHP 8.4+ exposes `request_parse_body()`; a multipart body on an unusual
method can reach the parser where apps do not expect it.

**First three checks** 1. Method used. 2. Is the endpoint a PHP script? 3. Correlate with A1–A6.

**Known false positives** — Some web frameworks probe with `PUT`/`PATCH` multipart.

---

## A10 — Windows host indicators (Sigma + YARA)

**What it means.** PHP-on-Windows post-exploitation: `php.exe`/`httpd.exe` spawning a download
cradle or host/privilege reconnaissance, or YARA hits on session files / heap artefacts.

**First three checks**
1. Parent–child process chain (PHP → shell/`certutil`/`bitsadmin`/`whoami`/`net`).
2. Any file written under the webroot in the same window.
3. Outbound connections from the PHP process.

**Escalate immediately** — process creation from a PHP worker is a strong RCE indicator.


---

## A11 — Appliance / PAN-OS management plane (added 2026-10-23)

**What it means.** Palo Alto **PAN-OS / Panorama are affected** by both CVEs (no special config
required; fixes ETA 26–30 Oct). PAN-OS ships an embedded PHP management interface, so the same
request shapes in this package apply — but on appliance management traffic rather than a web farm.

**First three checks.**
1. Is the management interface reachable from an untrusted network? That is the decisive risk
   factor; PAN states risk is highest when the MGT interface is internet-exposed.
2. Is the **full current** PAN Threat Prevention ID list enabled (as of 24 Oct this is 25 IDs:
   `543004`, `97622`–`97625`, `97643`, `97647`, `97649`, `97652`, `97653`, `97656`–`97659`,
   `97662`–`97664`, `97670`–`97674`, `97676`–`97678`; content **≥9164**) *and* actually seeing
   management traffic? Note the list expanded ~5× on 24 Oct — estates running only the original five
   are under-covered. Without MGT traffic routed through a DP port, certificate replacement and
   inbound decryption, the signatures do not protect the management plane.
3. Check PAN-OS/Panorama logs for unexpected HTTP POSTs to the management interface, and for
   `PHPSESSID` response cookies of abnormal length.

**Escalation.** Treat any positive A1 signal (oversized `PHPSESSID` response cookie) on an
appliance management interface as **P1** — these are security devices whose compromise yields
network-wide visibility and control, not just a single workload.

**Known FPs.** Appliance management UIs are usually low-traffic and predictable, so multipart
anomalies stand out more clearly than on application servers; normal admin backups/config pushes
may generate large multipart bodies — baseline them.
