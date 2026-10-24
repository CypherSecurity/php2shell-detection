# php2shell — CVE-2026-109618 / CVE-2026-109619 — Technical Handoff for RCE Analysis & Detection Engineering

> Self-contained brief. Goal: shared understanding of the RCE mechanics so we can
> build detections that key on exploit-internal artifacts, not just the obvious
> HTTP field names. Compiled 2026-10-21 from public research (sources at bottom).

## 1. Facts (high confidence)

- Two pre-auth RCEs in PHP core, CVSS v4.0 9.2 each. Nicknamed "php2shell".
- Embargo leaked 2026-10-20 (Tell HN post, deleted; screenshots on X/Mastodon).
  watchTowr confirmed real + reproduced 109618. PHP emergency release 2026-10-21 14:00 UTC.
- Affects PHP 5.4.0 – 8.5.11 (the vulnerable code is identical across 14 years).
- Fixed: **8.2.35, 8.3.36, 8.4.27, 8.5.12**. PHP ≤ 8.1 is EOL → permanent exposure.
- Exploit video (tool "php2shell", credited to Calif.IO) briefly circulated, pulled.
- Attack surface: `multipart/form-data` POST parsing (RFC 1867, `main/rfc1867.c`)
  and the session upload progress handler (`php_session_rfc1867_callback()` in
  `ext/session/session.c`). This code runs during request init — **before
  application code** — on ANY .php URL. App need not accept uploads. App-level
  middleware/CSRF/auth never sees it.
- CVE split (as publicly hypothesized): 109618 = upload_progress handler paths;
  109619 = multipart parser itself, triggers on ANY multipart POST regardless of
  `session.upload_progress.enabled`. This is why the ini mitigation is partial.

## 2. The four primitives

1. **Session fixation via POST body** — `MULTIPART_EVENT_FORMDATA` accepts a form
   field named `PHPSESSID` (matches `PS(session_name)`), overriding the cookie,
   ignoring `session.use_only_cookies`. Attacker controls session ID → controls
   session file name/path (`sess_<id>` in `session.save_path`). Fix: php-src PR #22113.
2. **Unvalidated filename injection** — `FILE_START` handler stores the raw
   client `filename` into the session data (`add_assoc_string_ex(..., *data->filename)`).
   No sanitization/encoding/length limit → `<?php` code or serialized payloads get
   persisted into `sess_*` files.
3. **Serializer leak across FPM requests** — `php_rshutdown_session_globals()`
   resets PS(id)/PS(session_vars)/etc. but NOT `PS(serializer)` → a session written
   by one serialize_handler can be decoded by another (cross-vhost, or cross-request
   on the same FPM worker).
4. **`var_destroy` reentry UAF + `__destruct` on decode FAILURE** —
   `var_destroy()` (ext/standard/var_unserializer.re) Phase 1 efree's extension
   chunks (~line 245), Phase 2 walks the dtor chain calling `i_zval_ptr_dtor()`
   (~line 310) **without `BG(serialize_lock)` held**. A `__destruct()` that calls
   `unserialize()` re-enters; `R:N;` back-references index into the freed
   `var_hash` → read of freed memory. ASAN-confirmed heap-UAF at var_unserializer.c:851.
   Critical property: `__destruct` fires on BOTH success and failure decode paths
   (PHP_VAR_UNSERIALIZE_DESTROY cleanup) — decode failure does not prevent exploitation.

## 3. The three verified chains (public research PoC, ikow/php2shell-poc)

| Chain | Path | Preconditions | Reliability |
|---|---|---|---|
| A | session file injection + LFI → include(sess file) → RCE | upload_progress=On (default) + any app LFI | ~100%, low complexity |
| B | var_destroy UAF → handler overwrite | reachable `unserialize()` w/ attacker data | ~60% (heap layout dependent) |
| C | handler mismatch (php_serialize vs php decoders) → `|` split → object deserialization → `__destruct` → POP chain | different serialize_handler dirs/vhosts OR FPM serializer leak | high |

Chain B internals (the pure memory-corruption route):
- unserialize payload with **2000+ entries** overflows `VAR_ENTRIES_MAX` (1018);
  a duplicate key moves an object to the dtor list
- Phase 1 frees chunks → Phase 2 `__destruct` (no lock) → inner
  `unserialize('R:1500;')` reuses outer var_hash → freed read
- heap spray reclaims chunk → controlled pointer → `var_dump`/handler overwrite
  → RCE on x86-64

## 4. Full weaponized chain (leaked tool / standalone exploit script)

Stages (each = observable artifacts, listed for detection):

1. **SEED** — craft trigger session: groom strings + `R:` reference layout.
   *Wire:* multipart POST with `PHP_SESSION_UPLOAD_PROGRESS` field (+ `PHPSESSID`
   field for fixation). *Server:* session file written with attacker layout.
2. **PRIME** — exhaust `memory_limit` mid-serialize. Worker **survives the fatal**
   (Apache prefork + mod_php, or any SAPI where the worker outlives a fatal);
   `BG(serialize)` left at level=1 with a **dangling `php_serialize_data`** (64-byte slot).
   *Server:* burst of `PHP Fatal error: Allowed memory size exhausted` + possible
   segfaults; HTTP 500s. Precondition: memory_limit small enough that a multi-MB
   session serialize fatals.
3. **TRIGGER** — back-to-back requests landing on the **same worker**; pre-RINIT
   serialize reuses stale context; `php_add_var_hash` walks it; attacker `R:`
   references drive `zend_hash_index_add_new` inserts.
   *Wire:* 2+ identical-shaped POSTs in quick succession, same session cookie/field.
4. **LEAK** — inserts corrupt an attacker-owned array with pointer-keyed entries;
   session write-back serializes them → **heap addresses readable in the session
   file** (requires reading the file back: app LFI, shared-hosting colocation, or
   local access). ASLR defeated.
   *Server:* sess file contains hex-looking pointer strings / malformed serialize data.
5. **RCE** — next trigger session sprays parts so a string recaptures the stale
   40-byte `zend_string`-class / 64-byte serialize_data slot; carries a forged
   `zend_fcall_info` + `zend_internal_function` pair → `zend_call_function` → `system(cmd)`.
   - Blob = **288 bytes** (matches blob in leaked tool), `n_spray` ≈ **149** parts.
   - Forged offsets (PHP 8.x, 64-bit LE) per the public exploit skeleton:
     `+0 size=64`, `+8 function/handler ptr`, `+16 type_info=0x106 (IS_STRING_EX)`,
     `+48 param_count=1`, `+64 type=ZEND_INTERNAL_FUNCTION`, `+152 handler ptr`,
     bytes at +200: `"system\0<cmd>\0"`.
   - Tool-specific boundary string observed in the paste: `BGCTXBOUNDARY` (do not
     key detections on it; per-tool).
   - End-to-end demo: ~20 s, Ubuntu 26.04 + Apache + mod_php, execution as `www-data`.

## 5. Detection surface (what exists today + gaps to close)

Existing rules key on: `PHP_SESSION_UPLOAD_PROGRESS` in multipart POST;
`name="PHPSESSID"` form field (fixation — near-zero FP); `filename="` +
`<?php`/`|O:N:"`/`R:N;` (payload — near-zero FP); ~60+ multipart parts spray
heuristic; PHP worker → shell/interpreter child (post-exploitation);
sess_* files containing `<?php`/`|O:`/binary/MB-size; burst 500/502 on .php POSTs.

**Gaps / questions for the RCE-side analysis (these would materially improve detections):**

> **UPDATE 2026-10-21 (post-release):** the official GHSA advisories answered most
> of these. Status per item below; section 7a has the official facts.

1. **109619 multipart-parser trigger shape** — **ANSWERED, and it was our biggest
   gap.** Official OOM strategies: (a) multipart POST **without usable
   Content-Length** (chunked) bypassing the initial `post_max_size` check;
   (b) **header flood inside one part** (headers amplified ~Nx in memory vs wire);
   (c) **empty file controls** (`filename=""` — exempt from `max_file_uploads` but
   still allocate metadata) + **deeply nested field names** (array work
   multiplication). NONE of these require `PHP_SESSION_UPLOAD_PROGRESS` or a
   malformed filename — our original rules would miss all three. Rules added
   (Suricata SIDs 2202610006-009, ModSecurity 2026106109-112).
2. **Request-size fingerprints** — **PARTIALLY ANSWERED:** the OOM strategies are
   amplification-based (within `post_max_size`, exhausting `memory_limit`), so
   simple "big body" thresholds are wrong. Shape-based rules (header-flood,
   empty-filename, nesting-depth) are the right approach; confirmed exploit ran
   with **default PHP input and memory limits** — no small-memory_limit
   precondition needed (corrects the earlier assumption).
3. **Same-worker affinity** — **CONFIRMED:** "demonstrated producing and consuming
   operations occur in different HTTP requests handled by the same worker."
   Producer fatals officially include OOM, `Maximum execution time exceeded`,
   parse/compile failures, uncaught errors, failed `require`, and nonfatal
   shutdown-stage diagnostics. Hunting widened accordingly.
4. **LEAK read-back path** — **NOT ADDRESSED** by the advisories (they describe no
   ASLR-leak stage; exploit reliability "depends on build, extensions, frontend
   behavior and allocator layout"). The leak/read-back question remains open for
   the researcher chains.
5. **FPM vs mod_php delta** — **ANSWERED DEFINITIVELY:** mod_php = confirmed
   app-independent pre-auth RCE (shutdown runs unconditionally after failed
   startup). FPM = child exits on startup failure; validated FPM path publishes
   state during app execution + fatal + upload-progress consumer (needs a
   cooperating app operation). FrankenPHP likely susceptible; LiteSpeed/LSAPI
   conditional/unvalidated.
6. **EOL backports** — **CORRECTION:** official minimal source backports now exist
   for 7.4/8.0/8.1 (php/php-src branches `PHP-7.4/8.0/8.1-CVE-2026-109618-109619`);
   distro/LTS vendors got advance patches. "No fix ever" was wrong.
7. **New producer knob (8.5):** `fatal_error_backtraces` state is the "basis of
   the confirmed mod_php exploitation" — audit/turn off on unpatched 8.5.

## 7a. Official advisory facts (GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp, 2026-10-21)

- **109618:** OOM handling used `longjmp()`; in contexts where request memory is
  reachable pre-initialization, ANY failed allocation leaves invalid state that
  request shutdown then consumes. Patch replaces longjmp with graceful soft-OOM
  at next VM safe point + hard-OOM `_exit()` at a second threshold.
- **109619:** producer/consumer model of stale worker-global → request-owned
  memory across requests on the same worker. Consumers: INI diagnostics before
  request init (mod_php per-dir `.htaccess`/`php_value`; FPM only when frontend
  sends `PHP_VALUE`/`PHP_ADMIN_VALUE` raising diagnostics; suppressing via
  `error_reporting`/`@`/`display_errors` does NOT help), and session upload
  progress reaching session handling before normal init (default-on, no
  `session_start()` needed).
- **Mitigation guidance (incomplete by design, update is the only fix):**
  `memory_limit=-1` via `php_admin_value` + worker restart (removes the
  predictable OOM; incomplete — mmap failure can still longjmp); conservative
  `post_max_size` + frontend enforcement of decoded size/part/field/header
  counts; `session.upload_progress.enabled=0` in php.ini/FPM config (NOT
  `ini_set`/`.user.ini`) + restart; 8.5 `fatal_error_backtraces=0`;
  **do NOT use `RLIMIT_AS`/`RLIMIT_DATA`** (forces mmap failure → the vulnerable
  longjmp path). cgroup limits have master/worker kill caveats.

## 6. Safety note

A "PoC bundle" archive circulates from third-party hosts; Phoenix Security assessed
it unverified/potentially malicious. Use only the research repos below, in
disposable labs, against 127.0.0.1 targets only.

## 7. Sources

- Sansec: https://sansec.io/research/php2shell (tool credit, mass-exploit expectation)
- watchTowr FAQ: https://watchtowr.com/intelligence/php-cve-2026-109618-faq/
- Huntress: https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities (process-side detection guidance)
- Flawfence: https://flawfence.com/blog/en/php2shell-cve-2026-109618-cve-2026-109619-php-rce-vulnerability/ (UAF hypothesis, Flatt Security recording analysis: ASLR leak → www-data in ~20s)
- Flare: https://flareapp.io/blog/a-critical-php-vulnerability-what-we-did-and-what-you-should-do (prod mitigations, nginx multipart block)
- Phoenix Security: https://phoenix.security/php-core-rce-cve-2026-109618-109619-critical-remote-code-execution/ (evidence-first, bundle warning)
- Research PoC repo (chains, ANALYSIS.md, code refs): https://github.com/ikow/php2shell-poc — writeup: qideng.substack.com
- Lab + ASAN A/B: dev.to/slabb "php2shell lab demo" (digest-pinned vulnerable php:8.4 images)
- Standalone full-chain exploit skeleton (unvetted pastebin): codepastes.com/zzgsqk09h079300g
- Session fixation fix: https://github.com/php/php-src/pull/22113
- Related historical bug (handler mismatch): https://bugs.php.net/bug.php?id=71101
- var_destroy UAF standalone: https://github.com/dinosn/php-8.5.5-var_destroy-uaf
