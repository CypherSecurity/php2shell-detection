# PHP2Shell — Heap Memory Disclosure via PHPSESSID Response Cookie
## Detection pack for the *silent* attack path (no RCE, no shell, no crash)

**Why this file exists.** The post-disclosure write-ups (Wiz, 2026-10-21) revealed an
attack my previous detections did not cover and that most 21-Oct rule packs miss:
CVE-2026-109619 can be used for **unauthenticated remote process-memory disclosure
without achieving code execution**. That has two consequences for defenders:

1. It is the *stealthiest* exploitation mode — no webshell, no child process, no
   segmentation fault, no fatal-error storm. Host EDR rules that look for
   "PHP worker → /bin/sh" will never fire.
2. The exfiltrated bytes (passwords, session tokens, API keys, certificates from
   *other* requests on that worker) are **returned to the attacker inside a
   `PHPSESSID` response cookie**, which is the single most reliable place to catch it.

### Mechanism (from the Wiz deep-dive + Calif write-up, 2026-10-21)
- PHP parses RFC1867 multipart bodies in `php_hash_environment()` **before**
  `zend_activate_modules()`; session upload-progress can publish a session id into
  `PS(id)` at this pre-init stage.
- A controllable OOM fatal aborts the request **before the multipart END callback and
  before session RSHUTDOWN run**, so the request heap is freed while `PS(id)` still
  points into it (worker survives on mod_php; on FPM the same class is reachable via
  post-startup application decode paths).
- On a **later multipart request to the same worker** (one that reaches
  `MULTIPART_EVENT_END` without `FILE_START` — i.e. **no file part**), the
  upload-progress cleanup initialises the session and trusts the stale `PS(id)`
  pointer/length as a live `zend_string`.
- PHP then **URL-encodes the reclaimed heap region into the `PHPSESSID` response
  cookie**. Attacker-sized region, attacker-chosen session id length ⇒ variable-length
  leak. Works even if the application never calls `session_start()`.

### What that looks like on the wire (the detection premise)
| | Normal `Set-Cookie: PHPSESSID=…` | Leak `Set-Cookie: PHPSESSID=…` |
|---|---|---|
| Value length | 22–32 chars (PHP default id is 26) | **32 chars up to attacker-chosen (config `session.sid_length`, default 26; the stale length is the *previous request's* id string — but the *content* is heap)** |
| Charset | `[A-Za-z0-9,-]` only (PHP session id alphabet) | contains `%XX` **percent-escapes**, raw non-alnum, or is not valid for the configured alphabet |
| Shape | random uniform | may contain **readable ASCII fragments** (paths, SQL, HTML, tokens), high entropy or repeated patterns |
| Context | one per login/anonymous session | appears on a request that carried **multipart + no file part**, often pairs with a preceding OOM/500 |

**The decisive, near-zero-false-positive signal:** a `Set-Cookie: PHPSESSID=` whose
value is **not composed solely of the session-id alphabet** (i.e. it contains `%`,
or characters outside `[A-Za-z0-9,-]`), *or* whose length materially exceeds the
configured `session.sid_length`, *or* whose value decodes to printable non-alphabet
content. PHP's own `session_id()` validation means a well-behaved app can never emit
such a cookie.

---

## 1. Suricata (response-side, needs HTTP response body/header inspection)

```suricata
# 2202610200 — PHPSESSID response cookie carrying percent-escapes (heap disclosure)
# High fidelity: legitimate PHP session ids are drawn from [A-Za-z0-9,-] and never
# percent-encoded. This fires on the memory-disclosure primitive.
alert http any any -> any any (msg:"ET LOCAL php2shell CVE-2026-109619 heap disclosure - percent-encoded PHPSESSID response cookie"; flow:established,from_server; http.response_header; content:"Set-Cookie|3a|"; nocase; http.response_header; content:"PHPSESSID="; nocase; http.response_header; pcre:"/Set-Cookie\x3a[^\r\n]*PHPSESSID\x3d[^\r\n;]*%[0-9A-Fa-f]{2}/i"; classtype:attempted-recon; sid:2202610200; rev:1; metadata:created_at 2026_10_21, cve CVE-2026-109619, affected_product PHP;)

# 2202610201 — PHPSESSID response cookie with non-alphabet characters
# PHP session ids use [A-Za-z0-9,-]. Anything else (e.g. '+', '/', '=', '.', ':', '"')
# means the value was not produced by the session-id generator.
alert http any any -> any any (msg:"ET LOCAL php2shell CVE-2026-109619 heap disclosure - PHPSESSID cookie with non-alphabet bytes"; flow:established,from_server; http.response_header; pcre:"/Set-Cookie\x3a[^\r\n]*PHPSESSID\x3d[^\r\n;]*[^A-Za-z0-9,\-%]/i"; classtype:attempted-recon; sid:2202610201; rev:1; metadata:created_at 2026_10_21, cve CVE-2026-109619;)

# 2202610202 — abnormally long PHPSESSID response cookie (>= 64 chars)
# Default session id length is 26. 64+ is a strong outlier; tune to your config
# (session.sid_length). Catches long stitched leaks even if fully alphanumeric.
alert http any any -> any any (msg:"ET LOCAL php2shell CVE-2026-109619 heap disclosure - oversized PHPSESSID response cookie"; flow:established,from_server; http.response_header; pcre:"/Set-Cookie\x3a[^\r\n]*PHPSESSID\x3d[A-Za-z0-9,\-]{64,}/i"; classtype:attempted-recon; sid:2202610202; rev:1; metadata:created_at 2026_10_21, cve CVE-2026-109619;)

# 2202610203 — leak-shaped request: multipart with NO file part and an upload-progress
# field (the MULTIPART_EVENT_END-without-FILE_START consumer trigger).
# Complements the existing spray/filename rules: this is the *quiet* consumer.
alert http any any -> [$HOME_NET,$HTTP_SERVERS] any (msg:"ET LOCAL php2shell CVE-2026-109619 consumer request - multipart upload-progress with no file part"; flow:established,to_server; http.method; content:"POST"; http.request_header; content:"Content-Type|3a 20|multipart/form-data"; nocase; file.data; content:"PHP_SESSION_UPLOAD_PROGRESS"; file.data; content:!"filename="; classtype:attempted-recon; sid:2202610203; rev:1; metadata:created_at 2026_10_21, cve CVE-2026-109619;)
```

## 2. ModSecurity / Coraza (response phase)

```apache
# Requires: SecResponseBodyAccess Off (cookies are in headers, phase:3/4).
# 2026106301 — PHPSESSID response cookie that violates the session-id alphabet.
SecRule RESPONSE_HEADERS:Set-Cookie "@rx (?i)PHPSESSID=[^;]*[^A-Za-z0-9,\-]|PHPSESSID=[^;]*%[0-9A-Fa-f]{2}" \
  "id:2026106301,phase:4,log,deny,status:403,msg:'php2shell CVE-2026-109619: PHPSESSID response cookie is not a valid session id (heap disclosure)',tag:'CVE-2026-109619',severity:'CRITICAL'"

# 2026106302 — oversized PHPSESSID (tune 64 to 2x your session.sid_length)
SecRule RESPONSE_HEADERS:Set-Cookie "@rx (?i)PHPSESSID=[A-Za-z0-9,\-]{64,}" \
  "id:2026106302,phase:4,log,deny,status:403,msg:'php2shell CVE-2026-109619: oversized PHPSESSID response cookie (possible heap disclosure)',tag:'CVE-2026-109619',severity:'HIGH'"

# 2026106303 — detect-only variant for the first 48h (alphabet rule), to baseline
SecRule RESPONSE_HEADERS:Set-Cookie "@rx (?i)PHPSESSID=[^;]*%" \
  "id:2026106303,phase:4,pass,log,msg:'php2shell CVE-2026-109619 TUNING: percent in PHPSESSID response cookie',tag:'CVE-2026-109619',severity:'LOW'"
```

**Deployment note:** denying here means the *victim* browser loses the cookie, which
is the correct defensive choice during an active leak — but it breaks the session for
that user. Start with 2026106303 (`pass,log`) and promote to `deny` on confirmation.

## 3. Sigma (webserver/proxy logs with response-header visibility)

```yaml
title: PHP2Shell Heap Disclosure - Invalid or Oversized PHPSESSID Response Cookie
id: 3f9a1c72-5d84-4b21-8e6f-1a2b3c4d5e6f
status: experimental
description: >
  Detects the CVE-2026-109619 memory-disclosure primitive. PHP url-encodes reclaimed
  worker-heap bytes into the PHPSESSID response cookie. A legitimate PHP session id is
  26 chars from [A-Za-z0-9,-] and is never percent-encoded, so any Set-Cookie
  PHPSESSID value containing '%', non-alphabet bytes, or length >= 64 indicates the
  stale-PS(id) disclosure path. Application-agnostic: fires even if the app never
  calls session_start(). PREREQUISITE: log source must record RESPONSE headers
  (proxy/WAF with response logging; plain access logs do not include Set-Cookie).
references:
  - https://www.wiz.io/blog/php2shell-php-rce
  - https://calif.io/php2shell.x/
  - https://www.php2shell.com/
author: php2shell detection research
date: 2026/10/21
logsource:
  category: webserver
detection:
  selection_cookie:
    response_headers|contains: 'PHPSESSID='
  # percent-escape anywhere in the value => not a PHP session id
  sel_percent:
    response_headers|re: '(?i)PHPSESSID=[^;\s]*%[0-9A-Fa-f]{2}'
  # char outside the PHP session alphabet (allow the '-' and ',')
  sel_badalphabet:
    response_headers|re: '(?i)PHPSESSID=[^;\s]*[^A-Za-z0-9,%\-;\s]'
  sel_oversized:
    response_headers|re: '(?i)PHPSESSID=[A-Za-z0-9,\-]{64,}'
  condition: selection_cookie and (sel_percent or sel_badalphabet or sel_oversized)
falsepositives:
  - Proxies or frameworks that re-encode cookies (verify on a sample before alerting)
  - Non-PHP apps that happen to use a cookie named PHPSESSID (rare; tune by app inventory)
level: critical
tags:
  - attack.collection
  - attack.credential_access
  - cve.2026-109619
```

## 4. Correlation rule (the actual attack pattern)

The disclosure needs **two beats**: a producer that dies pre-cleanup, then a consumer
that harvests. Alert on the *sequence*, not the cookie alone:

```yaml
title: PHP2Shell Producer->Consumer->Cookie Leak Sequence (CVE-2026-109619)
id: 8c1d2e3f-4a5b-6c7d-8e9f-0a1b2c3d4e5f
status: experimental
description: >
  Correlates the three observable beats of the silent disclosure chain on one
  client/worker within a short window:
   (1) producer: a request that dies pre-cleanup (multipart POST -> HTTP 500 and/or
       'Allowed memory size ... exhausted in Unknown on line 0'),
   (2) consumer: a later multipart POST WITHOUT a file part
       (PHP_SESSION_UPLOAD_PROGRESS + no filename=) to the same host, and
   (3) leak: the response carries an invalid/oversized PHPSESSID Set-Cookie.
  Each beat alone is noisy; the ordered triple is not.
references:
  - https://www.wiz.io/blog/php2shell-php-rce
logsource:
  category: webserver
detection:
  producer_500:
    sc-status: 500
    cs-method: 'POST'
    cs-content-type|contains: 'multipart/form-data'
  consumer_no_file:
    cs-method: 'POST'
    cs-content-type|contains: 'multipart/form-data'
    request_body|contains: 'PHP_SESSION_UPLOAD_PROGRESS'
    request_body|re: '(?s)^(?!.*filename=).*$'
  leak_cookie:
    response_headers|re: '(?i)PHPSESSID=[^;\s]*(%[0-9A-Fa-f]{2}|[^A-Za-z0-9,%\-;\s])'
  timeframe: 5m
  condition: producer_500 or consumer_no_file or leak_cookie   # refine to sequence in SIEM
level: critical
tags: [attack.collection, cve.2026-109619]
```

## 5. What this adds to the detection posture

| Attack mode | Covered previously? | Covered now |
|---|---|---|
| RCE via OOM + mod_php | partially (arm/kill shapes) | yes + official OOM shapes |
| RCE via FPM app-level decode stale state | **no** | partially (producer/consumer correlation) |
| **Silent heap disclosure (no RCE)** | **no** | **yes — this file** |
| OPcache cross-worker type confusion | no | hunting only (see note) |
| Recon/probe tooling (`php2shell.site` etc.) | no | see hunting-queries-v2 |

**OPcache type confusion note (CVE-2026-109619 variant):** shared-memory corruption
between workers leaves no per-request wire signature. Detection is limited to
(a) OPcache statistics anomalies (`opcache_get_status()` shared-memory restarts /
unexpected invalidations), (b) `opcache.enable_cli=0` + opcache restart counters
jumping, and (c) worker SIGSEGV storms on otherwise-healthy hosts. Treat as a hunting
query, not an alert. The patch covers all variants, which is why patching beats tuning.

## 6. Tuning checklist

1. Confirm your PHP `session.sid_length` (default 26) and allowed alphabet; set the
   oversized threshold to ~2.5x (64 is safe for defaults).
2. Confirm your proxy logs response headers; if not, the Suricata/ModSecurity rules
   are the only options.
3. Baseline 24–48h with `pass,log`; expect near-zero hits — this is not a noisy signal.
4. Be aware that the *same* `PHPSESSID` name is used by legitimate apps; the discriminator
   is the **character set / length**, never the name alone.
5. If this fires: treat the worker as compromised for **confidentiality** (tokens, keys,
   other users' data may have left the box), rotate secrets reachable by the PHP user,
   and patch immediately. RCE may not have occurred — but the data loss is real.