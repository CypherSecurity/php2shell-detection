# FALSE-POSITIVE TUNING & BASELINE

Goal: get from "rules deployed" to "analysts trust the queue" without muting real coverage.
Budget roughly **one week** of `pass,log` before any `deny`.

## 1. Deploy in monitor mode first

| Engine | Monitor-mode guidance |
|---|---|
| Suricata | Ship rules as-is; do **not** add `drop`. Confirm load (`-T`) and that alerts reach `eve.json`. |
| ModSecurity | `SecRuleEngine DetectionOnly` initially (the shipped config already uses `pass,log` for the canary tier). |
| Zeek | Notices are informational by default — good. |
| Sigma | Route to a **tuning index**, not the main case queue, for the first 48 h. |
| YARA | Run on demand/scheduled against session dirs, not on every file. |

## 2. Confirm you are actually receiving alerts

A ruleset that fails to load is silent. Before trusting coverage:

1. `suricata -T -S php2shell-v2.rules -c /etc/suricata/suricata.yaml` → expect **exit 0**.
2. Replay a benign-but-matching request (e.g. a multipart POST with 120 empty fields) and
   confirm at least one alert appears with an expected SID.
3. Confirm the same for ModSecurity by sending a `Content-Type: multipart/form-data` body on a
   non-POST method and checking the audit log.

**If step 2 produces nothing, you have no coverage — fix that before tuning.**

## 3. Baseline worksheet

For each rule family, record the first 48 h rate against *known-good* traffic. Mute or tune
only when you can name a legitimate cause.

| Rule family | Expected baseline on healthy traffic | Tune by |
|---|---|---|
| A1 oversized `PHPSESSID` | **~0** | Nothing to tune — investigate every hit |
| A2 NUL `PHPSESSID` | **~0** | Nothing to tune |
| A3 giant filename 64 KB+ | ~0 (rare tooling) | Allow-list specific upload endpoints/IPs if a known tool matches |
| A4 arm receipt / fire | ~0 | Do not tune; fix correlation instead |
| A5 `Session object destruction failed` | ~0 | Nothing to tune |
| A6 OOM producer/consumer pair | **low but non-zero** | Require same worker pid + 60 s; suppress known batch jobs by host |
| A7 part flood / 100+ parts | **moderate** on upload-heavy apps | Raise part threshold per app; allow-list upload endpoints |
| A8 no-Content-Length multipart | low–moderate | Allow-list known integrations by UA + source |
| A9 multipart on non-POST | low | Allow-list REST API paths that legitimately use PUT/PATCH |

## 4. Allow-lists you will probably need on day one

- **Your own vulnerability scanners** (internal Assetnote/Nuclei/Qualys sweeps) — they will
  generate these request shapes. Suppress by source IP **and** keep the suppression reviewed.
- **Backup / sync agents** that POST multipart without `Content-Length`.
- **Bulk import endpoints** (CSV/zip uploaders) that legitimately send many parts.
- **Load balancers / WAFs** that rewrite `Set-Cookie` (see A1 false positives).

Store allow-lists as **IP + host + rule-id**, never as "disable the rule".

## 5. Per-engine tuning knobs

**Suricata**
- `2202610102` part-header flood: threshold is 100+ header lines. If an app legitimately
  exceeds it, scope the rule to that host group by editing the `$HTTP_SERVERS` variable.
- `0111/0112` flow correlation: known to under-fire when `Connection: close` breaks flow
  state. **Prefer host logs** for this signal; do not "fix" by loosening to fire on any 500.

**Zeek**
- `Multipart_Part_Flood` threshold is >100 parts. Raise per-site if upload forms are large,
  but keep a low-tier notice at 500+ for high-value hosts.
- `Multipart_Midbody_Stall` is timing-based; on high-latency links it can be noisy — raise the
  stall window rather than removing the notice.

**ModSecurity**
- Request-shape rules are `phase:1`/`phase:2` `deny`. Before enabling deny in production,
  confirm they do not break legitimate uploads on that vhost.
- Response canaries use `phase:5` and require **`SecResponseBodyAccess On`** to see bodies —
  they will not fire otherwise. Verify that setting per vhost.

**Sigma / host logs**
- The strongest, least noisy signals are host-side: `Allowed memory size … exhausted … in
  Unknown on line 0` and `Session object destruction failed`. Tune `memory_limit`-related
  noise at the app, not by muting the rule.

## 6. Periodic re-checks (recommended)

| Cadence | Task |
|---|---|
| Weekly | Confirm `suricata -T` still passes after rule updates |
| Weekly | Review suppressions; remove stale IP allow-lists |
| Monthly | Re-baseline A6/A7 rates; they drift with app changes |
| On release | When a new PHP security release ships, re-verify version coverage across the fleet |

## 7. What NOT to tune away

- **A1 / A2 / A5** have essentially no legitimate cause. If they are noisy, the cause is a
  sensor or logging bug, not the rule.
- **A6** should be tuned by tightening correlation, not by disabling — a lone OOM line is not
  an alert, but the *pair* is the best host-side RCE indicator we have.
