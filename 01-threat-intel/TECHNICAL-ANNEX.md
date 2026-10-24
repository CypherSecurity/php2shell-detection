# PHP2Shell Technical Annex — Root Cause & Detection Engineering
**CVE-2026-109618 / CVE-2026-109619 · compiled 2026-10-21 (pre-patch, from public PoC analysis)**

Sources: jackalsyn PoC bundle (SHA256 `74adf2c4eb82776553837d185bae165494288747b43437fd452021a6ff6a93f0`, hash-verified), Calif.IO PHP2Shell video screenshot (via @wdormann / @GossiTheDog), Sansec, HN thread #50172041. Static analysis only — nothing was executed.

---

## 1. Root cause (source-level)

The vulnerable code is **`php_session_rfc1867_callback`** in `ext/session/session.c` — the **session upload-progress** feature (introduced in **PHP 5.4**, which is why the tool banner says "PHP >= 5.4.0").

**Ordering flaw:** the callback runs inside `php_hash_environment()`, **before** `zend_activate_modules()` and therefore **before `PHP_RINIT_FUNCTION(basic)`** zeroes the var-layer globals `BG(serialize)` / `BG(unserialize)` (basic_functions.c:393–395). Both globals cache `{ level, data }`.

**The trigger:** a `memory_limit` bailout inside the pre-RINIT `update()` decode/encode skips the corresponding `*_DESTROY`:

- **Bug S (serialize context)** — `PS_SERIALIZER_ENCODE_FUNC(php)` (session.c:1079–1108) runs `PHP_VAR_SERIALIZE_INIT … DESTROY` with **no `zend_try`**. An OOM bailout in `php_var_serialize` (smart_str_erealloc) leaves `BG(serialize).level = 1` with `.data` pointing at an orphaned 64-byte `php_serialize_data` (HashTable: `pDestructor=ZVAL_PTR_DTOR`, `uint32 n` at +0x38).
- **Bug U (unserialize context)** — `php_session_decode` (session.c:274–288) has a `zend_try`; the **`zend_catch` path calls `php_session_cancel_decode()` then `zend_bailout()` without `PHP_VAR_UNSERIALIZE_DESTROY`** → `BG(unserialize).level = 1`, `.data` points at an orphaned 8208-byte `php_unserialize_data` (last/first_dtor ptrs + embedded `var_entries` with 1018 `zval*` slots).

`shutdown_memory_manager(0)` then frees the context allocation while `BG(*).data` still points at it. **On the next request served by the same process**, `php_var_serialize_init` / `php_var_unserialize_init` see `level != 0` (var.c:1349 / var_unserializer.re:63) and **reuse the freed block as the live context → cross-request heap UAF**.

**Exploitation primitives:**
- `php_add_var_hash` (`data->n += 1` at var.c:756) — 4-byte read/write on freed+0x38 (Rina's ASAN receipt).
- `tmp_var()` (var_unserializer.re:157–185) — reads `last_dtor`(+16)/`used_slots` from the reclaimed block → `var_push_dtor` writes a 16-byte copied zval (**arbitrary value+type_info write**).
- `var_access()` (211–228) — `R:n;` markers in the session payload resolve `entries.data[n]` from forged bytes → **arbitrary `zval*` injected** as reference → dtor on next `zend_hash_update` → `zval_ptr_dtor(attacker_address)` → forged `zend_object` handlers → **`zend_call_function(fci,fcc)` → `zif_system`**.

> Analytic note: the *originally leaked* "cached bucket pointers" chain is **dead** — `Z_TRY_ADDREF(progress->data)` at session.c:3213 keeps the array alive, so no free occurs (this is the "retraction" seen on HN). The two CVEs correspond to the **two orphaned context globals** above. Calif's working chain uses the same class of primitive (leak `zval_ptr_dtor`/`zend_call_function` → forged `pDestructor` → call).

## 2. Exploit chain (what traffic looks like)

| Stage | Traffic | Purpose |
|---|---|---|
| **ARM** | Unauthenticated multipart POST: `PHPSESSID=<attacker-chosen>` field + `PHP_SESSION_UPLOAD_PROGRESS=x` field + ~20 file parts `upload0..19` with **256 KB filenames** (`f0-` + 262,144 × `N`), body ≈ 5.2 MB (variant: single 1.8 MB filename). Optional **slow-drip**: mid-body stall ~1.35 s (chunked) to hit `session.upload_progress.min_freq=1` | Drives repeated `update()` decode/encode rounds; filename bytes land in `current_file["name"]`; OOM → bailout → context orphaned. Server returns **HTTP 500** ("Allowed memory size … exhausted in Unknown on line 0"), **worker survives on prefork** |
| **FIRE** | Same session (same process): early parts reclaim the freed block — Bug U: `s[]` parts with ~8.2 KB values (3-page allocs), spray ≈ 80–120 + 600 small `t[]` parts + 6 KB file parts `f`,`g`; Bug S: `t[]` parts ≤ 39 bytes (64-byte bin). Then the file part triggers the first pre-RINIT `update()` whose INIT reuses the forged context | Forged context → arbitrary write / forged `pDestructor` → `zend_call_function("system", cmd)` |

**Calif "php2shell.py" video facts:** `--profile 21` (`ubuntu2604-php85`), target ABI **Ubuntu 26.04 package PHP 8.5.4 x86-64, builds 8.5.4-0ubuntu1 → 8.5.4-0ubuntu1.3**, SAPI boundary **Apache prefork/mod_php**, retry envelope **attempts=8 / timeout=25s**, leak of `main_heap`, `stale_reference`, `zval_ptr_dtor`, `zend_call_function` (ASLR defeated via reflected leak: "compact natural_tables=149"), in-band `system('uname -a; id; echo "pwned" > …/uploads/pwned.txt')`, chain complete in **15.1 s**, commands run as **uid=33 (www-data)**. The profile system exists because **offsets are per-build** (deltas e.g. bookworm 0xc930 / noble 0xcef0 / jammy 0xd060) — explaining the "requires a known binary" observation.

**Prerequisites:** attacker-chosen session ID accepted (`session.use_strict_mode=0`, the default), `session.upload_progress.enabled=1` (default), `memory_limit` small relative to `post_max_size` (e.g. 8M vs 8M bodies), and a SAPI whose worker survives the bailout.

## 3. SAPI / platform exposure matrix

| SAPI | Chain outcome |
|---|---|
| **Apache prefork + mod_php** | Full chain (RCE) — both labs' primary target |
| `php -S` (built-in server) | Survives arm; chain plausible — treat as exposed |
| **PHP-FPM / CGI** | Worker exits on startup-failure bailout → **DoS only** in tested config ("unless the OOM lands post-startup") |
| LiteSpeed LSAPI (lsphp) | Exits on R1 per jackalsyn; "unverified, test empirically" in ROOT_CAUSE — do not assume safe |

Version floor **5.4** (feature introduction) → all supported 8.x affected. glibc matters for reclaim reliability: **glibc 2.39 (Ubuntu 26.04)** demonstrated; Debian 12 (2.36) not reproduced by jackalsyn — absence of public repro ≠ safety.

## 4. Mitigations — including newly-discovered configuration controls

1. **`session.upload_progress.enabled = Off`** — closes **both** paths (session.c:3239). Lock with `php_admin_flag` in every FPM pool (a `.user.ini` can re-enable it otherwise). Side effect: native upload-progress bars break.
2. **`session.use_strict_mode = 1`** — blocks attacker-chosen session IDs (the `PHPSESSID` form-field fixation the chain depends on).
3. **`memory_limit` ≥ ~4× `post_max_size`** (e.g. limit 256M with post_max_size 8M) — verified control: "arm impossible, clean 200" (bundle control R6-2a). Conversely **lowering `post_max_size`** (e.g. 1M) rejects pressure bodies (R6-2b).
4. Block multipart at the web server (all methods — PHP 8.4 `request_parse_body()` covers PUT/PATCH) — nginx `if ($http_content_type ~* multipart) { return 444; }`, Apache `<If "req('Content-Type') =~ /multipart/i"> Require all denied </If>`.
5. Patch at 14:00 UTC: **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12** (per Alpine GitLab). Remi repo users get nothing today — switch sources. PHP ≤8.1: no fix → isolate.

## 5. Detection engineering

### 5.1 Network / WAF (high-signal request patterns)
- **`PHP_SESSION_UPLOAD_PROGRESS` part + attacker-set `PHPSESSID` part in the same multipart body** — the combo is near-unique to this exploit family (legit apps set one via cookie, not as form fields together). *Strongest single rule.*
- **Filename length anomalies**: `filename="` + ≥65,536 bytes (256 KB / 1.8 MB observed) — no legitimate filename is that long. Regex on `filename="[^"]{65536,}`.
- **Repetitive same-name parts**: ≥50 parts named `s[]`, `t[]`, `upload\d+`, or `f`/`g` in one body; part counts 80–600 observed.
- **Mid-body stall**: multipart POST where inter-chunk gap ≈ 1–2 s on a sessionized endpoint (min_freq timing arming). Zeek: `conn` intervals with T≈1.3 s inside multipart POSTs.
- **8 attempts / 25 s retry envelope** from one source against one URL with multipart bodies.
- Multipart on **non-upload endpoints** (e.g. `/wp-content/index.php` — a PHP file directly under wp-content is itself anomalous), and multipart **PUT/PATCH**.
- Marker bytes: runs of `0x43`/`0x44` qwords (`0x4343434343434343` nNextFreeElement, `0x4444444444444444` pDestructor) in bodies.

### 5.2 Web server / PHP logs (exact strings)
- `PHP Fatal error: Allowed memory size of ... bytes exhausted` **in `Unknown on line 0`** immediately following a multipart POST → HTTP 500 (arm stage).
- Warning pair in later requests: **`Session ini settings cannot be changed when a session is active`** + **session open failure with `PS(save_path)` dangling** ("open(…, O_RDWR) failed") = orphaned serialize context evidence.
- mod_php/prefork **child SIGSEGV** (apache2 error log) after multipart bursts from one IP.
- Alert on the *sequence*: multipart-500-with-OOM → subsequent 200s from same IP+session = armed host.

### 5.3 Host / EDR
- **www-data / php-fpm worker spawning processes** (`uname`, `id`, `sh`, `curl`, `wget`, `python`) within seconds of a multipart request — the in-band `system()` pattern.
- New files in upload dirs written by www-data without corresponding app upload (the `pwned.txt` pattern); new/modified `.php` under `wp-content/`, `uploads/`, `mu-plugins`; `.user.ini` and `auto_prepend_file` changes.
- New cron/systemd/supervisor entries, new SSH keys, outbound connections from the PHP user.
- Hunt queries: `apache2|php-fpm ImageLoadOf shell` ; `find /var/www -type f -newermt '2026-10-20 15:00 UTC'`.

### 5.4 Sigma-style rule (example, webserver category)
```yaml
title: PHP2Shell Upload-Progress Arm Pattern
detection:
  selection_method:
    cs-method: 'POST'
    c-content-type|contains: 'multipart/form-data'
  selection_fields:
    c-body|contains|all:
      - 'name="PHP_SESSION_UPLOAD_PROGRESS"'
      - 'name="PHPSESSID"'
  condition: selection_method and selection_fields
level: critical
```
(Adjust to your WAF's body-logging capability; the two-field combo is the discriminator. Add a sibling rule for `filename="` length > 64 KB.)

## 6. Artifact inventory (local, in `php2shell-intel/`)
- `gossithedog-screenshot.jpeg` — original HN leak post (petecooper): CVSS 10.0 claim, 22 Oct 18:00 CEST plan, CVE IDs
- `calif-php2shell-tool.png` — Calif.IO tool frame: profiles, leaked pointers, executed `system()`, uid=33, 15.1 s chain
- `jackalsyn-php-up-2026.html` / `jackalsyn-extract.txt` — full corrected write-up
- `php2shell-reup.zip` + extracted `php2shell-reup/` — PoC bundle (**do not execute outside an isolated lab; authorized targets only**) incl. `ROOT_CAUSE.md`, `php2shell_repro.sh` (self-contained lab with PASS/FAIL receipts and **control tests** R4/R6), `poc_serialize.py`, `poc_unserialize.py`, `fast_fire.py`
- `wdormann-thread.jpeg` — thread screenshot
