# INCIDENT RESPONSE — php2shell

Use when a **P1** fires (A1 disclosure cookie, A5 session-destruction) or when a P2
(A2/A3/A4) targets an **unpatched** host. Two different outcomes, two different responses:

- **Disclosure (A1)** → assume **credentials/secrets already stolen**. Containment alone is
  not enough; **rotation is mandatory**.
- **RCE attempt (A2–A6)** → containing the code-execution path is time-critical.

---

## Step 0 — Establish exposure state (5 minutes)

Answer these before anything else; they change the priority:

| Question | Why |
|---|---|
| Exact PHP version + SAPI (mod_php / FPM / CGI) | Determines which chains apply |
| Is version ≥ 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35? | Fixed versions close both CVEs |
| **Were workers restarted after the upgrade?** | Stale state survives a package update — an upgraded host that did not restart is **still vulnerable** |
| `display_errors` effective value | On → public RCE path available |
| Is the host internet-facing? | Severity multiplier |

## Step 1 — Contain

**Best:** patch to a fixed release **and restart the PHP workers** (`systemctl restart
apache2` / `php-fpm`; a graceful reload is *not* sufficient for stale-state issues).

**If patching cannot happen immediately**, apply in this order (all are compensating, not
fixes):
1. `session.upload_progress.enabled = 0` — breaks the upload-progress arm used by every
   known chain. **Highest-value single control.**
2. Lower `max_multipart_body_parts` — published chains need **≥1,902** parts; a low cap breaks
   this specific exploit.
3. Set `display_errors = Off`, `log_errors = On` — removes the easy output-based leak and RCE
   path.
4. Keep `memory_limit` bounded via **cgroup / container limit**, not `RLIMIT_AS`/`RLIMIT_DATA`
   (those change failure modes without preventing the OOM).
5. If compromise is suspected: **take the service offline or read-only.**

## Step 2 — Preserve evidence

Before restarting or rebuilding:
- Copy **web server access/error logs** and **PHP error logs** for the affected window.
- Capture **PCAP** if available (the malicious requests are cleartext multipart).
- Snapshot the **session directory** (`session.save_path`) — `sess_*` files may hold attacker
  artefacts.
- On Windows: export process creation logs and any YARA hits from the session dir.

## Step 3 — Scope (do not start at 21 October)

**Amazon Threat Intelligence confirmed exploitation attempts from 2026-10-17**, four days
before public disclosure. Search from **17 October 2026** forward.

Look for:
- `Allowed memory size … exhausted … in Unknown on line 0` on PHP workers
- `Session object destruction failed` at PHP Request Startup
- Worker restarts / `SIGABRT` / `zend_mm_heap corrupted` bursts
- Requests with **≥1,902 multipart parts**, or giant `filename="…"` values
- **Oversized `PHPSESSID` response cookies** — the disclosure artifact
- Post-exploitation: files under webroot, `passthru`/`system` traces, outbound connections
  from web workers, new cron jobs, `php.exe`/`httpd.exe` spawning shells (Windows)

Use `../04-hunting/hunting-queries-v2.md` — the queries are written for this window.

## Step 4 — Rotate (mandatory for any A1 disclosure)

Memory disclosure means the attacker could read **any request's data on that worker**. Treat
as a secret-exposure event:

- **Invalidate all sessions** for the affected app (delete session files / rotate session
  keys) — assume session tokens were captured.
- Rotate **application secrets**: `.env`, DB credentials, API keys, JWT/signing keys,
  payment/plugin credentials.
- Rotate **TLS/SSH keys** only if they were reachable in process memory on that host
  (common for CLI-configured apps — assess).
- Review auth logs for use of captured credentials **after** the disclosure event.

## Step 5 — Notify

Follow your own incident/regulatory process. Inputs worth having ready:
- Confirmed vulnerable window (patch date minus worker-restart date)
- Whether disclosure (A1) occurred — this drives breach-notification analysis
- Scope across customers, if you are a service provider

## Step 6 — Verify the fix held

- Confirm `php -v` on **every** node, not just the template/AMI.
- Confirm **worker restart time** > upgrade time.
- Confirm the canary request no longer produces the arm artifact (re-run a benign multipart
  flood against a staging clone of the host).
- Keep detections running — they are version-independent and cost little.

---

## Escalation triggers (call IR, do not self-resolve)

- P1 disclosure cookie observed in a response to an external client
- Producer→consumer OOM pair on the same worker **plus** any post-exploitation indicator
- `Session object destruction failed` paired with a preceding OOM on an unpatched FPM host
- Same source IP hitting **multiple customers** — coordinated campaign
- PHP worker spawning a shell, download utility, or reconnaissance binary

## Common mistakes

- **Upgrading without restarting workers** — leaves stale state exploitable.
- **Restarting before collecting logs** — destroys the best evidence.
- **Containing the RCE but skipping rotation after a disclosure event** — the attacker may
  already hold valid credentials.
- **Treating `display_errors=Off` as mitigation** — it blocks one path, not the disclosure.
- **Scoping from the patch date** — misses up to four days of precursor activity.
