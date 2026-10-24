# Hunting queries — php2shell (CVE-2026-109618 / CVE-2026-109619)

Layered from cheapest (log-only) to most decisive. Run #1 and #2 first — they need
nothing but access logs and process telemetry.

---

## 1. Access-log anomaly hunt (works with plain nginx/Apache logs, no body needed)

The exploit's *shape* is visible without bodies: bursts of POSTs to `.php` URLs
that never received multipart traffic before, followed by worker errors.

**Splunk (nginx):**
```spl
index=web sourcetype=nginx:plus http_method=POST uri_path="*.php"
| stats count, dc(uri_path) as paths, values(status) as statuses by src_ip, _time span=1m
| where count >= 5
| sort - count
```

**Error-correlation (PRIME stage causes worker fatals / 502s):**
```spl
index=web sourcetype=nginx:plus (status=500 OR status=502 OR status=413) uri_path="*.php"
| stats count by src_ip, uri_path, status
| where count >= 3
```

**Elastic KQL:**
```
http.request.method:POST and url.path:*.php and (http.response.status_code:500 or http.response.status_code:502)
```

**Raw grep (ship to analyst):**
```bash
# POSTs to php endpoints by unusual clients, with error statuses
grep -E 'POST [^ ]+\.php ' access.log | grep -E ' (500|502|413) '
```

## 2. Request-body hunts (WAF audit logs / proxies with body capture)

```spl
index=waf sourcetype=modsec:audit
| search "PHP_SESSION_UPLOAD_PROGRESS" OR "name=\"PHPSESSID\"" OR "filename=\"<?php"
| stats count values(client_ip) as src values(host) as vhost by rule_msg
```

```bash
grep -rE 'PHP_SESSION_UPLOAD_PROGRESS|name="PHPSESSID"|filename="<?(php|=)' /var/log/modsec_audit.log
# serialized-object variant (Chain C):
grep -rE 'filename="[^"]*\|O:[0-9]+:|R:[0-9]+;' /var/log/modsec_audit.log
```

## 3. Session-file forensics on PHP hosts (Chain A / C artifacts land here)

Session files live in `session.save_path` — typically `/var/lib/php/sessions`,
`/var/lib/php/sessions`, `/tmp`, or `/var/tmp`. Look for:

```bash
# PHP code or serialized objects inside session files (never benign)
grep -rlE '<\?php|<\?=|\|O:[0-9]+:' /var/lib/php/sessions/ /tmp/ 2>/dev/null | grep sess_

# recently-touched session files that are LARGE (LEAK stage writes heap addresses;
# PRIME uses multi-MB sessions) or contain binary
find /var/lib/php/sessions /tmp -name 'sess_*' -mmin -30 -size +100k 2>/dev/null

# attacker-fixed session IDs: files whose name isn't a normal hash (32 hex chars)
ls /var/lib/php/sessions | grep -Ev '^sess_[a-f0-9]{26,32}$' | head

# upload_progress keys with weird key names (attacker controls the key)
grep -rl 'upload_progress_' /var/lib/php/sessions/ | head
```

Confirm what the config actually is before hunting:
```bash
php -i | grep -E 'session.save_path|upload_progress|serialize_handler|use_strict_mode'
```

## 4. Host triage — is a box already popped?

```bash
# PHP workers with unexpected children (the decisive signal)
pstree -p | grep -A2 -E 'php-fpm|httpd|apache2'
ps -eo pid,ppid,user,cmd --sort=start_time | grep -E 'php|httpd' | head -50

# reverse-shell / one-liner patterns in any process cmdline or shell history
grep -rE '/dev/tcp/|mkfifo|fsockopen|bash -i|sh -i' /proc/*/cmdline 2>/dev/null
grep -rE '/dev/tcp/|mkfifo|fsockopen' /home/*/.bash_history /root/.bash_history 2>/dev/null

# webshells dropped in docroots after Oct 21
find /var/www -name '*.php' -newermt '2026-10-21' -not -path '*/vendor/*' 2>/dev/null
```

Florian Roth's free `process-watcher` in observe mode is a solid stopgap on
Linux fleets without an EDR.

## 5. Config audit (exposure + weakness inventory)

```bash
# version + patch level against fixed versions (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)
php -v

# vulnerable feature enabled? (default = ON = exposed)
php -r 'echo ini_get("session.upload_progress.enabled"), PHP_EOL;'

# serialize_handler mismatches across vhosts (Chain C precondition)
find /var/www -name '.user.ini' -o -name 'php.ini' -o -name 'vhost.conf' \
  | xargs grep -l 'serialize_handler' 2>/dev/null
```

### Config audit additions — from the official advisories (2026-10-21)

The advisories add SAPI-specific exposure facts and producer-side fatals. Audit for:

```bash
# PHP 8.5 only: fatal_error_backtraces is the STRONGEST confirmed stale-state
# producer ("basis of the confirmed mod_php exploitation"). Turn it off on
# unpatched 8.5 until patched:
php -r 'echo ini_get("fatal_error_backtraces"), PHP_EOL;'   # 1 = exposed extra producer

# memory_limit posture: finite limits are REQUIRED for the confirmed exploit
# (attacker needs a predictable OOM). Unpatched stopgap = memory_limit=-1 via
# php_admin_value (FPM pool / Apache vhost), then verify nothing reapplies a
# finite limit (pool conf, .htaccess php_value, .user.ini):
grep -RnsE 'memory_limit' /etc/php* /etc/php.d /etc/php-fpm.d 2>/dev/null
grep -Rns 'php_value memory_limit\|php_admin_value memory_limit' /etc/httpd /etc/apache2 2>/dev/null

# FPM-specific consumer: frontends passing PHP_VALUE / PHP_ADMIN_VALUE FastCGI
# params that raise INI diagnostics before request init (advisory-listed consumer).
# This is a config-side exposure — not attacker-controlled, but widens attack surface:
grep -Rns 'fastcgi_param PHP_VALUE\|fastcgi_param PHP_ADMIN_VALUE' /etc/nginx 2>/dev/null

# per-request size ceilings (OOM strategy resistance) — advisory recommends:
# conservative post_max_size, bounded max_input_vars / max_input_nesting_level /
# max_file_uploads, and frontend enforcement of decoded request size
php -i | grep -E 'post_max_size|max_input_vars|max_input_nesting_level|max_file_uploads|upload_max_filesize'

# EOL PHP (7.4/8.0/8.1): official minimal source backports NOW EXIST:
#   https://github.com/php/php-src branches PHP-7.4-CVE-2026-109618-109619,
#   PHP-8.0-CVE-2026-109618-109619, PHP-8.1-CVE-2026-109618-109619
# Distro/LTS vendors received patches in advance; remirepo lags — check yours.
```

**SAPI exposure ranking (official):** mod_php = confirmed app-independent pre-auth
RCE (startup-failure shutdown runs unconditionally). FPM = susceptible but the
confirmed path needs a cooperating application operation + upload-progress consumer
(FPM kills the child on startup failure). FrankenPHP = likely susceptible like
mod_php. LiteSpeed/LSAPI = conditional, unvalidated.

**Producer fatals to hunt beyond OOM** (any of these followed seconds later by
another request from the same client = stale-state producer/consumer pairing):
`Allowed memory size ... exhausted`, `Maximum execution time of ... exceeded`,
`PHP Parse error` / `PHP Compile error`, uncaught `Error`/`Exception`,
failed `require`. PHP-FPM log side: child exits / segfaults
(`child ... exited on signal`, `SEGV`) right after large POSTs.

## 6. What to escalate immediately

| Observation | Meaning |
|---|---|
| `filename="<?php` or `filename="x\|O:8:` in any logged body | Confirmed exploit attempt |
| `PHPSESSID` as a POST form field | Session-fixation primitive in use |
| sess_* file containing `<?php` / `\|O:` | Chain A/C landed — treat as incident |
| php-fpm child = sh/curl/python | Successful RCE — isolate, image, hunt persistence |
| Burst of 500/502 on one vhost + one source | PRIME-stage grooming — block source, check for follow-on |
