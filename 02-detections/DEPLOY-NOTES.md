# Deployment notes — read before loading

## Suricata REQUIRED config (or body rules never fire)
Default request-body inspect window is 8KB — far too small.
```yaml
app-layer:
  protocols:
    http:
      libhtp:
        default-config:
          request-body-limit: 2mb
          request-body-inspect-window: 1mb
```
Plus `pcre.match-limit: 200000`. Ensure HTTP/1.1 chunked body inspection is on.

## Don't load v1 + v2 together
v2 supersedes v1 (different anchors/thresholds, adds flowint arm tracking).
Loading both double-alerts. v1 kept in `v1-rules-superseded/` as reference only.

## Flow correlation caveat
Rules 0111/0112 use per-flow `flowint`. Public PoC sends `Connection: close`, so arm
and fire land on different flows — **0112 rarely fires**. Durable cross-flow signal is
the host log line `Allowed memory size ... exhausted ... in Unknown on line 0`.

## ModSecurity phase note
Canaries 211–215 use `phase:5` (LOGGING). `phase:4` (RESPONSE_BODY) is skipped when
`SecResponseBodyAccess` is Off (default) — phase-4 canaries would never execute.

## Response-side rules
Heap-leak detection needs response-header inspection: see
`../02-detections/DETECTION-MEMORY-DISCLOSURE.md`.

## Zeek
Base-only, no packages. `@load php2shell.zeek` from site/local.zeek; thresholds are `&redef`.

---

## Suricata 8.x compatibility fixes — 2026-10-22

The ruleset was validated against **Suricata 8.0.3** (`suricata -T`, exit 0, 0 errors).
Four defects that prevented the entire ruleset from loading were found and fixed. If you
deployed an earlier build of this package, **re-deploy the `.rules` file** — an earlier
version failed to load completely, meaning **no php2shell alerts at all**.

| Defect | Symptom | Fix applied |
|---|---|---|
| `flowint:name,set,1` | `detect-flowint: ... is not a valid setting` — rule rejected | Suricata has **no `set` modifier**; assignment is `flowint:name,=,1` |
| `{65536,}` / `{1048576,}` in pcre | `number too big in {} quantifier` — rule rejected | PCRE2 caps quantifiers at **65535**; 1 MB rule now uses 17 × `{65535}` blocks |
| `http.content_len; less_than:1048576;` | `unknown rule keyword 'less_than'` | Dropped; the negative-lookahead `Content-Disposition` test already gives specificity (per-packet `dsize` cannot express body size) |
| `pcre:"/.../[^;].../"` | `bad option value formatting` — the `;` inside a pcre class is parsed as an option separator | Escaped as `\x3b` |

**Lesson worth repeating:** an unloadable ruleset fails *silently* in many pipelines — the
sensor keeps running and simply produces zero alerts for this threat. Always run
`suricata -T -S php2shell-v2.rules` and confirm load in staging before trusting coverage.

### New rules added 2026-10-22
- `sid:2202610114` — NUL byte in `PHPSESSID` cookie (raw). A real PHP session id is 26
  chars of `[A-Za-z0-9,-]` and can never contain NUL. This is an **arm-stage** signal.
- `sid:2202610115` — percent-encoded `%00` in `PHPSESSID`.

Both target a detail published with the public exploit: it sets `PHPSESSID=\x00` to force
PHP to mint a new session id while leaving session state dirty.

## v2.2 deploy note — boundary-first rules (2026-10-26)

SIDs **2202610122–124** are new. `…122` (kit boundary `B7kQpoc618`) is the highest-precision network
signal we have — it needs no payload inspection and no body-size tuning. `…123` catches fixed
single-character boundaries (the public tool uses `CCCCCCCCCC`). `…124` exists to **exclude** the
WordPress `wp2shell` look-alike, not to count it.

SIDs `…100`/`…101` were revised to add a **`Next-Action` header exclusion** after Fastly measured the
chunked-multipart-no-Content-Length signature as **98.6% React2Shell (CVE-2025-55182)**. Treat those two
as *medium* confidence context, not the primary signal.
