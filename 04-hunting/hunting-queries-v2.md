# Hunting queries v2 — php2shell (CVE-2026-109618 / CVE-2026-109619)

Companion to `../sigma/` (v2 rules) and `../yara/php2shell.yar` (session-file
content verdicts). Every string quoted below was captured
**verbatim in the 2026-10-21 validation lab** — they are not paraphrases of the
advisories. Two stacks were used: Ubuntu 24.04 + Apache 2.4.58 prefork +
mod_php 8.3.6 (primitive confirmation) and Ubuntu 26.04 + PHP 8.5.4 + mod_php +
glibc 2.43 (parity, kill/corruption cascade).

Replace before running:
- `index=web` / `index=php` / `index=os` — your access, PHP-error and process indexes.
- `sourcetype=access_combined` / `php_error` / `ps` — your sourcetypes.
- Field names: this set assumes `src_ip`, `method`, `uri`, `content_type` for
  access logs and `message`, `host`, `pid` for PHP error logs. Apache's
  `[pid 704:tid 704]` prefix needs extraction (`rex "\[pid (?<pid>\d+)"`);
  nginx/FPM logs usually have `pid` already parsed.

Severity ladder (same as v1): access-log shape < error-log artifact <
same-worker producer/consumer pair < process/file evidence of execution.

---

## 1. Splunk SPL

### 1.1 `Allowed memory size of ... in Unknown on line 0` + multipart POST, same src_ip, 60 s

The ARM event. The `in Unknown on line 0` marker is the discriminator: a normal
application OOM names a real script and line, so this combination is rare.

```spl
(index=web sourcetype=access_combined (method=POST OR cs_method=POST) uri="*.php"
   (content_type="multipart/form-data*" OR cs_content_type="multipart/form-data*"))
OR (index=php sourcetype=php_error "PHP Fatal error: Allowed memory size of" "in Unknown on line 0")
| eval src=coalesce(src_ip, clientip, c_ip, c-ip)
| eval is_post=if(isnotnull(uri),1,0), is_fatal=if(searchmatch("Allowed memory size of"),1,0)
| stats sum(is_post) as posts sum(is_fatal) as fatals min(_time) as first max(_time) as last
        values(uri) as uris by src
| where posts>0 and fatals>0 and (last-first)<=60
| sort - fatals
```

*Noise:* LOW-MODERATE — multipart POSTs are common on upload apps, so the
60 s join and the `Unknown on line 0` requirement carry the precision; a
single-source pair is worth an alert, a fleet-wide pattern is worth a block.

Subsearch variant when the two logs are in different indexes and you want the
error event's timestamp/pid attached:

```spl
index=web sourcetype=access_combined method=POST uri="*.php" content_type="multipart/form-data*"
| stats min(_time) as post_time by src_ip
| join type=inner src_ip
    [ search index=php sourcetype=php_error "PHP Fatal error: Allowed memory size of" "in Unknown on line 0"
      | rex "\[pid (?<pid>\d+)"
      | stats min(_time) as fatal_time values(pid) as pids by clientip
      | rename clientip as src_ip ]
| eval delta=fatal_time-post_time
| where delta>=0 AND delta<=60
```

*Noise:* LOW — but `join` caps at 50k subsearch rows; constrain the window.

### 1.2 `zend_mm_heap corrupted` with a 30-day baseline

Allocator-detected corruption → SIGABRT. Captured immediately before the abort
on the parity stack.

```spl
index=php sourcetype=php_error earliest=-30d "zend_mm_heap corrupted"
| bin _time span=1d
| stats count by host, _time
| eventstats avg(count) as avg_daily stdev(count) as sd_daily max(count) as peak by host
| where count > max(1, avg_daily + 3*coalesce(sd_daily,0))
| sort - count
```

*Noise:* NEAR-ZERO on hosts with a flat baseline. On a host that has **never**
logged it, a single occurrence is the alert — run the same search with
`earliest=-30d` as a weekly sanity check and keep a `zend_mm_seen_hosts` lookup
if you need "first ever" semantics. Caveat: a few PHP builds log this on known
opcache/JIT bugs, so confirm the build before paging.

### 1.3 Session-warning cluster (orphaned / dangling session state)

```spl
index=php sourcetype=php_error
  ("Session ini settings cannot be changed when a session is active"
   OR "Failed to read session data" OR "Failed to write session data"
   OR "session_encode(): Cannot encode non-existent session"
   OR "open(" )
| rex "\[pid (?<pid>\d+)"
| eval artifact=case(
    searchmatch("Session ini settings cannot be changed"),"stale-ini",
    searchmatch("Cannot encode non-existent session"),"orphan-encode",
    searchmatch("Failed to read session data") OR searchmatch("Failed to write session data"),"session-io",
    searchmatch("in Unknown on line 0/sess_"),"dangling-save-path",
    true(),"other")
| stats count min(_time) as first max(_time) as last values(artifact) as artifacts
        values(message) as lines by host, pid
| where count>=2 OR artifacts="dangling-save-path"
```

*Noise:* LOW — these warnings are rare on healthy workers; the dangling
`in Unknown on line 0/sess_` path is effectively a zero-FP corruption fingerprint
and should alert on a single occurrence.

### 1.4 Zombie worker count metric (`STATE=Z`)

```spl
index=os sourcetype=ps host=*
| where process_name IN ("apache2","httpd","php-fpm") AND state="Z"
| bin _time span=5m
| stats count as zombies dc(pid) as distinct_zombies by host, process_name, _time
| where zombies >= 5
```

If your ps input uses `STAT`/`process_state` instead of `state`, swap the field;
the Splunk metric you want is literally `| stats count by host, process`.

*Noise:* LOW after baselining — one or two transient zombies during a graceful
restart is normal; a monotonically growing count across a multipart-POST burst
is the php2shell worker-kill artifact (12 observed in the lab).

### 1.5 Producer → consumer on the SAME worker pid (60 s)

```spl
index=php sourcetype=php_error
  ("PHP Fatal error" OR "PHP Parse error" OR "PHP Compile error"
   OR "Maximum execution time" OR "Uncaught Error" OR "Uncaught Exception"
   OR "Failed opening required"
   OR "Session ini settings cannot be changed when a session is active")
| rex "\[pid (?<pid>\d+)"
| eval kind=if(searchmatch("Session ini settings cannot be changed"),"consumer","producer")
| transaction pid maxspan=60s
| where eventcount>=2
        AND mvcount(mvfilter(kind=="producer"))>0
        AND mvcount(mvfilter(kind=="consumer"))>0
| table _time, host, pid, duration, producer_message, consumer_message
```

*Noise:* LOW — `transaction` is memory-hungry, so scope to the PHP error index
and a narrow window. Cheaper stats form (recommended at fleet scale):

```spl
index=php sourcetype=php_error earliest=-1h
| rex "\[pid (?<pid>\d+)"
| eval kind=if(searchmatch("Session ini settings cannot be changed"),"consumer","producer")
| stats min(eval(if(kind=="producer",_time,null()))) as p_time
        max(eval(if(kind=="consumer",_time,null())))  as c_time
        values(eval(if(kind=="producer",message,null()))) as producer
        values(eval(if(kind=="consumer",message,null()))) as consumer
        by host, pid
| where isnotnull(p_time) AND isnotnull(c_time) AND c_time>=p_time AND (c_time-p_time)<=60
```

*Noise:* LOW — same-worker fatal→stale-session pair within 60 s is the official
CVE-2026-109619 signature and was reproduced verbatim in the lab.

---

## 2. Elastic (EQL / KQL)

### 2.1 EQL sequence: multipart POST → pre-init OOM, same client IP

```eql
sequence by source.ip with maxspan=60s
  [any where event.category == "web"
       and http.request.method == "POST"
       and http.request.mime_type : "multipart/form-data*"]
  [any where event.dataset == "php.error"
       and message : "PHP Fatal error: Allowed memory size of*"
       and message : "*in Unknown on line 0*"]
```

*Noise:* LOW-MODERATE — requires both events to carry `source.ip`; if the PHP
error pipeline has no client IP, enrich from the access log before using EQL
(otherwise use the KQL pair below and correlate in the UI).

### 2.2 EQL sequence: producer fatal → stale-session consumer, same pid

```eql
sequence by process.pid with maxspan=60s
  [any where event.dataset == "php.error"
       and message : ("PHP Fatal error*" or "Maximum execution time*" or "PHP Parse error*")]
  [any where event.dataset == "php.error"
       and message : "*Session ini settings cannot be changed when a session is active*"]
```

*Noise:* LOW — requires `process.pid` extracted from the `[pid N]` prefix at
ingest (grok `\[pid %{NUMBER:process.pid}`). The correlation is the product;
either line alone is not worth paging on.

### 2.3 KQL: single-event artifacts (alert candidates)

```
message:"Allowed memory size of" and message:"in Unknown on line 0"
```

```
message:"zend_mm_heap corrupted"
```

```
message:("Session ini settings cannot be changed when a session is active"
         or "session_encode(): Cannot encode non-existent session"
         or "Failed to read session data" or "Failed to write session data")
```

```
message:* and message:"/sess_" and message:("in Unknown on line 0" or "Warning" or "Fatal")
```

*Noise:* line 1 LOW (pre-init marker required), line 2 NEAR-ZERO (baseline
per host), line 3 LOW but keep as a correlation candidate, line 4 NEAR-ZERO
(dangling `PS(save_path)` corruption fingerprint).

### 2.4 KQL: heap corruption history (30 d baseline)

```
event.dataset:"php.error" and message:"zend_mm_heap corrupted"
```

Run with a 30-day window, then `Visualize → Date histogram (1d) split by host`.
*Noise:* NEAR-ZERO — flat-zero hosts that suddenly log this are the priority;
sustained single-host logging is a build/lab issue.

---

## 3. Microsoft Defender XDR (KQL)

### 3.1 PHP/host process spawning shells and system utilities

Core parent/child logic lives in `win_proc_php_rce_child.yml`; this query adds
the php2shell post-exploitation shapes (recon, log clearing, tasks, cradles).

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","php-fpm.exe","httpd.exe","apache.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","certutil.exe","bitsadmin.exe",
                      "curl.exe","mshta.exe","rundll32.exe","whoami.exe","net.exe","net1.exe",
                      "wevtutil.exe","schtasks.exe","reg.exe","nltest.exe","systeminfo.exe","wmic.exe")
| extend shape = case(
    ProcessCommandLine has_any ("wevtutil cl","Clear-EventLog","Remove-EventLog"), "log-clear",
    ProcessCommandLine has_any ("schtasks","Register-ScheduledTask","New-ScheduledTaskAction"), "scheduled-task",
    ProcessCommandLine has_any ("whoami /priv","whoami /groups","net user","net localgroup","nltest","systeminfo"), "recon",
    ProcessCommandLine has_any ("DownloadString","DownloadFile","Net.WebClient","IEX(","urlcache","bitsadmin /transfer","FromBase64String"), "download-cradle",
    ProcessCommandLine has_any ("reg add","CurrentVersion\\Run","CurrentVersion\\RunOnce"), "run-key",
    "other-shell")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, FileName, ProcessCommandLine, shape
| sort by Timestamp desc
```

*Noise:* LOW on servers (PHP has no business spawning these), HIGH on developer
workstations — filter `DeviceName`/`DeviceType` to servers only.

### 3.2 Run-key / persistence written by PHP itself

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","php-fpm.exe","httpd.exe")
| where RegistryKey has_any (@"\CurrentVersion\Run\", @"\CurrentVersion\RunOnce\",
                            @"\CurrentVersion\Policies\Explorer\Run\")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          RegistryKey, RegistryValueName, RegistryValueData
```

*Noise:* LOW — legitimate PHP installers register autostart at install time;
allow-list the exact value, not the rule.

### 3.3 Multipart POST bursts against PHP (DeviceNetworkEvents — approximation)

Defender network telemetry carries **no HTTP method, MIME type, or body**, so a
true "multipart POST burst" is not observable here. The closest proxy is an
inbound-connection burst to the PHP/web listener, which is a scoping hint only:

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType in ("InboundConnectionAccepted","ConnectionSuccess")
| where InitiatingProcessFileName in~ ("php.exe","php-cgi.exe","httpd.exe","apache.exe","nginx.exe")
| summarize conns=count(), peers=dcount(RemoteIP), ports=make_set(RemotePort, 5)
            by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1m)
| where conns >= 20 and peers <= 3
```

*Noise:* MODERATE-HIGH — a busy upload endpoint looks identical. Use it to find
candidate hosts/time windows, then confirm with IIS/Apache access logs or the
WAF body query (v1 hunting doc §2). Honest limitation: no method/MIME visibility.

### 3.4 Session files (`sess_*`) written at anomalous size (DeviceFileEvents)

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| where FileName startswith "sess_"
| where FolderPath has_any (@"\Windows\Temp\", @"\tmp\", @"\sessions\", @"\session\", @"\php\")
| where FileSize >= 102400
| project Timestamp, DeviceName, FolderPath, FileName, FileSize,
          InitiatingProcessFileName, InitiatingProcessAccountName
| sort by FileSize desc
```

*Noise:* LOW-MODERATE — Windows PHP installs often put sessions in
`C:\Windows\Temp`, which is noisy; the `sess_` prefix + ≥100 KB filter carries
it. Content verdict (PHP tags / serialized objects) requires the
`Webshell_In_Session_File` scan from ../yara/php2shell.yar, not this query. Note Defender's `FileSize` is the size at
event time, not a delta.

---

## 4. grep / ripgrep one-liners (validated strings)

Point at Apache and FPM logs; rotated logs are often `.gz`, so use `rg -z` or
`zgrep`:

```bash
LOG_GLOBS='/var/log/apache2/error.log* /var/log/httpd/error_log* /var/log/php*fpm*.log* /var/log/php*.log*'
```

```bash
# ARM: pre-init OOM (the "Unknown on line 0" marker is mandatory)
rg -nz 'PHP Fatal error: Allowed memory size of.*in Unknown on line 0' $LOG_GLOBS

# Official CVE-2026-109619 consumer artifact (stale worker session state)
rg -nz 'Session ini settings cannot be changed when a session is active' $LOG_GLOBS

# Allocator corruption, immediately pre-SIGABRT
rg -nz 'zend_mm_heap corrupted' $LOG_GLOBS

# Orphaned session state
rg -nz 'session_encode\(\): Cannot encode non-existent session' $LOG_GLOBS

# Dangling PS(save_path): path field contains embedded prior log text
rg -nz 'open\([^)]*(in Unknown on line|Warning|Fatal)[^)]*/sess_' $LOG_GLOBS

# Session read/write failure whose (path: ...) is garbage
rg -nz 'Failed to (read|write) session data.*\(path: [^)]*(in Unknown on line|Warning|Fatal)' $LOG_GLOBS

# Worker death: Apache prefork/mod_php segfault, or FPM child signal 11
rg -nz 'exit signal Segmentation fault|child .* exited on signal 11|SIGSEGV' $LOG_GLOBS

# Official producer shape: max_execution_time hit at request init
rg -nz 'Maximum execution time of .* exceeded.*in Unknown on line 0' $LOG_GLOBS

# PHP 8.5 exploitation-enabling setting seen in a diagnostic
rg -nz 'fatal_error_backtraces' $LOG_GLOBS
```

*Noise:* OOM NEAR-ZERO with the `Unknown` marker; session-ini and heap-corrupted
NEAR-ZERO; generic `Failed to read/write session data` MODERATE (permissions and
GC races) — pair with the OOM line; segfault LOW (other crashes exist — check the
binary/core); `fatal_error_backtraces` NEAR-ZERO as a log string (it is a config
name, normally absent from runtime logs).

Quick combined triage on one host:

```bash
zgrep -hE 'Allowed memory size of.*in Unknown on line 0|zend_mm_heap corrupted|Cannot encode non-existent session|Session ini settings cannot be changed|in Unknown on line 0/sess_' \
  /var/log/apache2/error.log* /var/log/php*fpm*.log* 2>/dev/null | tail -50
```

---

## 5. Linux host triage (metric-shaped artefacts Sigma cannot express)

### 5.1 Zombie worker pile-up

```bash
ps -eo stat,ppid,pid,user,comm | awk '$1 ~ /^Z/ && $5 ~ /^(apache2|httpd|php-fpm)/ {print}'
ps -eo stat | grep -c '^Z'          # host baseline; compare over time
```

Alert when the count grows across a multipart-POST burst (lab: 12 zombies, one
per kill attempt). *Noise:* LOW-MODERATE — a couple of transient zombies around
restarts is normal; a monotonic climb is not.

### 5.2 Session-file flock held >5 s by an active worker

```bash
for p in $(pgrep -f 'php-fpm: pool'); do
  for fd in /proc/$p/fd/*; do
    t=$(readlink "$fd" 2>/dev/null) || continue
    case "$t" in */sess_*)
      awk -v f="$t" -v p="$p" '/^lock:/{print strftime(), p, f, $0}' \
        "/proc/$p/fdinfo/$(basename "$fd")" 2>/dev/null ;;
    esac
  done
done | sort | uniq -c | sort -rn | head
```

The deadlock artifact is the same (pid, sess_ path) pair holding a lock for
>5 consecutive seconds while the worker is still in R/S state with CPU — slow
disk alone does not look like that. *Noise:* LOW-MODERATE (busy session stores
show brief locks); sample twice and compare.

### 5.3 Session files with payload content / anomalous size (pairs with YARA)

```bash
# PHP tags or serialized objects inside session files — near-zero FP
rg -lz '<\?php|<\?=|\|O:[0-9]+:|R:[0-9]+;' /var/lib/php/sessions/ 2>/dev/null | grep sess_

# multi-MB / recently-touched sessions (PRIME + LEAK stages)
find /var/lib/php/sessions /var/lib/php/session /tmp -name 'sess_*' -mmin -60 -size +100k 2>/dev/null

# attacker-chosen (non-standard) session IDs
ls /var/lib/php/sessions 2>/dev/null | grep -Ev '^sess_[a-f0-9]{26,32}$' | head
```

*Noise:* size query LOW (legit large sessions exist — baseline per vhost);
PHP-tag grep NEAR-ZERO and should be treated as confirmed Chain A/C payload
together with `Webshell_In_Session_File` (../yara/php2shell.yar); odd session IDs
MODERATE (some frameworks use longer/custom IDs).

---

## 6. auditd / eBPF (invisible to process-creation telemetry)

### 6.1 PHP worker reading `/proc/self/mem` or `/proc/<pid>/mem`

In-process read-back produces no child, so the sigma rule only catches the
shell-out/debugger variants. To see the real thing, capture open() at the kernel:

```bash
# auditd: log opens of any process mem file (needs path-wildcard support or an eBPF sensor)
auditctl -a always,exit -F arch=b64 -S open,openat -F path=/proc/*/mem -k php2shell_memread

# then: which comm/user did it?
ausearch -k php2shell_memread -i | grep -E 'comm="(php-fpm|httpd|apache2)"|uid=33'
```

```bash
# eBPF/bpftrace alternative
bpftrace -e 'tracepoint:syscalls:sys_enter_openat /str(args->filename) ~ /\/proc\/.*\/mem$/ {
  printf("%s pid=%d comm=%s\n", strftime("%H:%M:%S"), pid, comm); }'
```

*Noise:* LOW after filtering gdb/valgrind/perf/coredump helpers — normal
workloads do not open `/proc/*/mem`.

### 6.2 Writes to session.save_path by a process other than the pool user

```bash
auditctl -w /var/lib/php/sessions -p wa -k php2shell_sesspath
ausearch -k php2shell_sesspath -i \
  | grep -E 'name=.*sess_' \
  | grep -vE 'exe="/usr/sbin/(php-fpm|httpd|apache2)"' \
  | grep -vE 'auid=33|uid=33'       # 33 = www-data; adjust to your pool uid
```

*Noise:* LOW — only backup/AV/indexing agents and distro `sessionclean` cron
should appear; allow-list those binaries explicitly.

---

## 7. Patch-status canary (find unpatched hosts)

Last vulnerable versions: **8.5.11 / 8.4.26 / 8.3.35 / 8.2.34** (and every
release below those lines; PHP 8.0/8.1/7.x are EOL → permanently vulnerable
unless you applied the official minimal backport branches).
Fixed: **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**.

### 7.1 Splunk — banner extraction from proxy/WAF response headers

```spl
index=proxy sourcetype=*:access earliest=-7d
| rex field=_raw "(?i)X-Powered-By:\s*PHP/(?<phpver>\d+\.\d+\.\d+)"
| rex field=_raw "(?i)\bServer:\s*(?<serverhdr>[^\r\n]+)"
| where isnotnull(phpver) OR match(serverhdr,"(?i)php")
| rex field=phpver "(?<vmaj>\d+)\.(?<vmin>\d+)\.(?<vpat>\d+)"
| eval vuln=case(
    isNull(vmaj),"unknown-banner-only",
    vmaj<8,"eol-vulnerable",
    vmaj=8 AND vmin<2,"eol-vulnerable",
    vmaj=8 AND vmin=5 AND vpat<=11,"vulnerable",
    vmaj=8 AND vmin=4 AND vpat<=26,"vulnerable",
    vmaj=8 AND vmin=3 AND vpat<=35,"vulnerable",
    vmaj=8 AND vmin=2 AND vpat<=34,"vulnerable",
    true(),"patched")
| stats latest(phpver) as phpver latest(vuln) as vuln latest(serverhdr) as server by dest
| where vuln IN ("vulnerable","eol-vulnerable","unknown-banner-only")
| sort by vuln, dest
```

*Noise:* the query is exact; the *data* is incomplete — `expose_php=Off` hides
`X-Powered-By`, and reverse proxies often rewrite `Server`. Treat a hit as
confirmed-vulnerable, a miss as unknown, never as patched.

### 7.2 Bash fleet scan (authoritative when headers are exposed)

```bash
while read -r h; do
  ver=$(curl -sSI --max-time 5 "https://$h/" 2>/dev/null </dev/null | tr -d '\r' \
        | awk 'BEGIN{IGNORECASE=1} /^x-powered-by:.*php\//{sub(/.*PHP\//,""); print; exit}')
  if [ -z "$ver" ]; then echo "$h,unknown,no-banner"; continue; fi
  st=$(awk -v v="$ver" 'BEGIN{
    split(v,a,"."); maj=a[1]+0; min=a[2]+0; pat=a[3]+0;
    if (maj<8) {print "eol-vulnerable"; exit}
    if (maj>8) {print "patched"; exit}
    if (min==5) print (pat<=11?"vulnerable":"patched");
    else if (min==4) print (pat<=26?"vulnerable":"patched");
    else if (min==3) print (pat<=35?"vulnerable":"patched");
    else if (min==2) print (pat<=34?"vulnerable":"patched");
    else print "eol-vulnerable";
  }')
  echo "$h,$ver,$st"
done < hosts.txt
```

*Noise:* none in the comparison; coverage limited by `expose_php` and proxy
header rewriting — for internal hosts prefer `php -v` / package version
inventory (authoritative) over banners.

### 7.3 Notes for Defender / Elastic

Neither platform captures HTTP response headers by default, so there is no
native banner query. Use (a) an authenticated/agentless scan against
`/phpinfo.php`-free endpoints (headers only), or (b) the package inventory:
`DeviceTvmSoftwareInventory` / `DeviceTvmSoftwareVulnerabilities` filtered on
`SoftwareName has "PHP"`, or Elastic `metrics`/osquery `deb_packages` /
`rpm_packages` for `php-fpm`/`php-cli` versions. Compare against the same
per-branch ceilings as §7.2. *Noise:* LOW, but inventory lags reality —
cross-check the service banner.

## H1. Public-exploit artefacts (`JoasASantos/php2shell-exploit`) — added 2026-10-24

Reproduced by us on 2026-10-24: pre-auth RCE with `display_errors=Off` when Apache prefork runs a
**single worker**. Artefacts are stable across runs and architectures.

**H1.1 Access-log search — webshell access / execution**

```text
# Splunk
index=web (uri_path="*/.p2s.php" OR uri_path="*/.p2s_v2.php")
| stats count min(_time) as first max(_time) as last by host, clientip, uri_path, uri_query, status
| convert ctime(first) ctime(last)
```

```text
# Elastic / KQL
http.request.uri.path : (*.p2s.php or *.p2s_v2.php)
```

**H1.2 Execution pattern** — `?c=` on a `*.p2s.php` path, plus the self-delete `?rm`:

```text
uri_query="*c=*" uri_path="*.p2s.php"
uri_query="*rm=*" uri_path="*.p2s.php"
```

**H1.3 Webroot sweep for planted shells** (also catches renamed copies by content):

```bash
grep -rIl --include='*.php' -e 'unlink(__FILE__)' -e 'isset($_GET["c"])' /var/www 2>/dev/null
find /var/www -name '.p2s*.php' -o -name '.p2s_v2.php' 2>/dev/null
```

**H1.4 `.htaccess` persistence (v2 technique)**

```bash
grep -rIl 'auto_prepend_file' /var/www 2>/dev/null
grep -rIl '.p2s_v2.php' /var/www 2>/dev/null
```

**H1.5 Session-directory residue** — the tool writes multi-MB session files during the OOM stage:

```bash
find /tmp /var/lib/php/sessions -maxdepth 1 -type f -size +2M -printf '%p %s %TY-%Tm-%Td %TH:%TM\n' 2>/dev/null
```

Hunt window: from **2026-10-17** (pre-disclosure attempts) onward.
