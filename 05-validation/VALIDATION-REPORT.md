# PHP2Shell — Lab Validation Report

**Date:** 2026-10-21 (pre-patch) · **Analyst:** Lead
**Objective:** determine empirically whether the circulating PHP2Shell PoC actually works, and validate the claimed detection/mitigation signals.
**Verdict (short):** ✅ **The vulnerability primitive is REAL and REPRODUCED** on an unaffected-by-ambiguity, vulnerable build. ❌ **Full end-to-end RCE (`system()`) was NOT achieved** with the public PoC — consistent with the public bundle's own admission. Detection signatures were validated against live traffic.

---

## 1. Test environment

Deliberately isolated: disposable Docker container, no host changes, lab binds `127.0.0.1` only inside the container.

| Component | Version | Why it matters |
|---|---|---|
| OS | Ubuntu 24.04.5 LTS (noble) | container base |
| glibc | **2.39** (`2.39-0ubuntu8.7`) | same series as Calif's working demo (2.39); jackalsyn's full chain failed on Debian 12 / glibc 2.36 |
| PHP | **8.3.6** (Ubuntu package, Oct 2026 build) | an affected branch — scheduled fix is 8.3.36 |
| SAPI | **Apache 2.4.58 prefork + mod_php** | the documented survivor SAPI for the cross-request UAF |
| Session upload progress | enabled (default) | the vulnerable code path |
| memory_limit / post_max_size | 8M / 32M | the pressure configuration the exploit requires |

**Why this is a fair test:** the lab reproduces every documented precondition (prefork survival, upload-progress on, low memory_limit relative to accepted body size, attacker-chosen session ID accepted because `session.use_strict_mode=0` default).

Artifacts: `php2shell-intel/lab/Dockerfile`, `receipt_experiment.sh`, `exp1-gdb-evidence.log`, `exp1-error.log`, `run-full-bundle.log`.

---

## 2. What was CONFIRMED

### 2.1 The ARM stage (pre-RINIT OOM with worker survival) — deterministic, reproduced repeatedly
Same body as the public PoC: multipart POST carrying `PHP_SESSION_UPLOAD_PROGRESS` + `PHPSESSID` + a 1.8 MB / multi-part 256 KB-filename upload.

```
[root@lab] ARM → HTTP 500
[php:error] PHP Fatal error: Allowed memory size of 8388608 bytes exhausted
            (tried to allocate 1802240 bytes) in Unknown on line 0
```
- **`in Unknown on line 0`** proves the fatal fires **before any application code** — the property that makes every PHP app exposed regardless of framework. This matches the CVSS 9.2 rationale.
- **Worker survived** the bailout (prefork), which is the gate for the cross-request UAF.

### 2.2 The orphaned serialize context + cross-request reuse — **the core CVE primitive**
gdb instrumentation on `php_var_serialize_init` reading the real context state (`basic_globals + 0x350` = level, `+0x348` = data), with semantics established from disassembly:
> `level == 0` → `_emalloc_64` fresh context · `level != 0` → **reuse existing data pointer**

Captured trace (verbatim, `exp1-gdb-evidence.log`):

```
S_INIT level=0 data=(nil)             ← ARM: allocate fresh context (level → 1)
                                      ← OOM bailout: NO destroy for this request
S_INIT level=1 data=0x7ffff666d140    ← FIRE (next request, same worker): level≠0
                                        → REUSES the orphaned block
S_DESTR entry level=2                 ← destroy only decrements, does NOT free
S_INIT level=1 data=0x7ffff666d140    ← reused again, identical pointer
S_DESTR entry level=2
```
Counters: after ARM `S_INIT=1, S_DESTR=0`; after FIRE `S_INIT=3, S_DESTR=2` (net +1 orphaned).

**Interpretation:** the context allocated during the ARM request was freed at request teardown but `BG(serialize).level` stayed `1` and `.data` still points at it. The next request on the same worker re-enters init with `level≠0` and **uses the freed block as the live serialization context** — exactly the cross-request heap UAF described in `ROOT_CAUSE.md`. This is the arbitrary-read/write surface behind **CVE-2026-109618**.

### 2.3 Corroborating log signature (validated, new for detection)
The documented "orphaned context" warning pair appeared on the follow-up request:
```
[php:warn] PHP Request Startup: Session ini settings cannot be changed
           when a session is active in Unknown on line 0
```
This is an observable, high-value **host-side detection** indicator (see §5).

### 2.4 Mitigation controls — all validated as effective
| Control | Result |
|---|---|
| `session.upload_progress.enabled=0` | identical body → **S_INIT=0, S_DESTR=0, zero reuse receipts**. The vulnerable callback never runs. |
| `memory_limit=256M` (≫ post_max_size) | arm impossible — body cannot carry enough pressure → clean 200 |
| `post_max_size=1M` | pressure body rejected at delivery → clean 200 |

Note: with `upload_progress=0` a generic multipart OOM can still occur when parsing an absurd filename, but the **serialize/unserialize context path — i.e. both CVEs — is entirely absent**. This matches PHP core's "only patching is sufficient" stance being *about completeness*, not about this setting being useless: it does close the documented callback paths (session.c:3239).

---

## 3. What was NOT confirmed

- **No end-to-end code execution.** The public bundle's own kill stage is labelled *"TUNED DEMO — ASLR brute required"*, and 12+ attempts produced no `SIGSEGV` and no `system()`. The bundle author's own `ROOT_CAUSE.md`/`README` concede: the leaked "cached pointer" chain is *structurally impossible* (`Z_TRY_ADDREF` at session.c:3213 keeps the tree alive) and the real bug is *memory-safety only (their rating: CVSS 5.3)* in their lab configuration.
- **Therefore:** the **9.2-severity RCE claim** rests on (a) the Calif.IO "PHP2Shell" tool video, which shows a full leak→forge→`system()` chain with **per-build offset profiles** (Ubuntu 26.04 / PHP 8.5.4 / glibc 2.39, 15.1 s, uid=33), and (b) Cloudflare's report of early exploitation. Neither could be independently reproduced here. **We confirmed the primitive, not the weaponization.**

### Reconciling the discrepancy (assessment)
The public PoC and the private tool differ exactly where it matters: **heap grooming + ASLR defeat for a specific build**. Our lab confirms the *memory-corruption precondition exists and persists across requests* — which is precisely what a weaponized chain needs. The honest position:
- Vulnerability exists: **confirmed**
- Public PoC achieves full RCE: **not demonstrated**
- A competent attacker with the private tool / build-specific offsets: **plausible and claimed by credible parties**

---

## 4. Reproduction instructions

```bash
cd php2shell-intel/lab
docker build -t php2shell-lab .            # legacy builder if buildx is sandboxed: DOCKER_BUILDKIT=0
docker run --name p2s -d --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
           php2shell-lab sleep infinity
docker exec p2s bash /lab/php2shell_repro.sh 18190     # bundle's 8-stage suite
docker exec -it p2s bash /tmp/receipt_experiment.sh    # level-based receipt experiment
```
Expected: bundle suite **7/8 PASS** (RCE#1 gdb stage fails due to *hardcoded struct offsets for PHP 8.1.2 inside the bundle's own gdb script* — a receipt artifact, not a refutation; our `receipt_experiment.sh` replaces it with correct symbol-based reads).

**Safety:** loopback-only inside a throwaway container; no host network exposure; PoC only against the lab's own Apache.

---

## 5. Detection implications (validated in-lab)

Now evidence-backed rather than theoretical:

1. **`PHP Fatal error: Allowed memory size ... exhausted ... in Unknown on line 0`** immediately following a multipart POST from a single client → **arm attempt**. Alert on this specific combination (generic OOMs are noisy; pre-RINIT + multipart is not).
2. **`PHP Request Startup: Session ini settings cannot be changed when a session is active in Unknown on line 0`** → orphaned/dangling session context = **exploitation aftermath**. Strong, low-false-positive indicator.
3. **HTTP 500 on a multipart upload-progress POST, then 200s from the same IP/session** → armed-then-probing pattern.
4. Multipart body containing **both** `name="PHP_SESSION_UPLOAD_PROGRESS"` and `name="PHPSESSID"` form parts → the exploit's signature shape.
5. `filename="` value ≥ 64 KB (1.8 MB / 256 KB observed) → no legitimate client does this.
6. Many repetitive same-name parts (`s[]`, `t[]`, `upload\d+`) and ~1–2 s mid-body stalls (min_freq arming).

---

## 7. PARITY REPLICATION (update, 21 Oct ~13:45 UTC) — testing it "the same way as the video"

The user asked whether we replicated the video's method. We hadn't — the public bundle **omits the leak stage** ("final system() call is ASLR-gated — pro weapon: 'leak' stage"), and the video's tool uses per-build profiles. To close the gap we rebuilt the video's exact stack:

**Parity environment** (`lab26/`): Ubuntu 26.04 ("resolute") + **PHP 8.5.4-0ubuntu1.4** (video targeted 8.5.4-0ubuntu1 → 1.3, same upstream patch family) + Apache 2.4.66 prefork + mod_php + **glibc 2.43**. Symbol delta verified against the video: `zval_ptr_dtor − zend_call_function = 0xBE3F0` (matches the video's leaked pair exactly).

### 7.1 Results on the matched stack — following the documented kill recipe exactly

| Step (per WEAPON_NOTES "KILL RECEIPT") | Our result |
|---|---|
| ARM: 1 file part, 1,800,000-byte filename → 500, pre-RINIT OOM, child survives | ✅ reproduced every attempt |
| fire#0 (150-spray) → 200 survive | ✅ reproduced every attempt |
| **fire#1 (250-spray) → worker killed mid-request** | ✅ **reproduced on first attempt, then ~12/12 total** (twelve zombie workers accumulated across attempts — each fire250 killed its worker; earlier "apache alive" readings were zombies, resolving the earlier hang-vs-crash ambiguity: **crash-class**) |
| Real leaked `zval_ptr_dtor` (ground-truth equivalent of the video's LEAKED stage) fed to the forge via `--pdtor` | ✅ **`zend_mm_heap corrupted` → SIGABRT (core dumped)** — allocator-detected corruption via the forged-pointer path |

### 7.2 Corruption cascade captured live (new detection evidence, `lab26/parity-error-evidence.log`)
After the kill sequence, the surviving worker's session machinery showed **`PS(save_path)` pointing into freed memory now holding old log text**:
```
PHP Warning: PHP Request Startup: open(t Startup: Session ini settings cannot be
changed when a session is active in Unknown on line 0/sess_u0123..., O_RDWR) failed
```
plus `session_encode(): Cannot encode non-existent session`. The save_path string pointer itself was dangling — the author's "PS(save_path) dangling" primitive, caught in the act.

### 7.3 What the parity test settles
- The **kill (worker memory-corruption) is deterministic-enough on the video's stack** — no exotic setup needed, matching the author's receipt and the video's 8-attempt envelope.
- **Full `system()` RCE was still not achieved** — the final stage requires the private **288-byte object forge** (video OCR: fields `0x40`, `0x106 IS_STRING_EX`, `1, 1`, `0x308 IS_OBJECT_EX`, `system`+command at `+0xc8`, 149× `t[]` parts, leak-gated). Reconstructing that reliably without the tool is beyond guesswork: the fake-object layout must survive `zend_hash_destroy`'s bucket walk and land a valid `zend_call_function(fci,fcc)` — several unknown offsets deep.
- **Honest bottom line:** primitive confirmed → kill confirmed → corruption-of-live-pointers confirmed → **RCE remains credibly claimed but not independently reproduced**. For defenders this changes nothing: treat as actively-exploited RCE (Cloudflare's in-the-wild observation), apply the validated mitigations, patch at 14:00 UTC.

### 7.4 Patch-drop retest (pending)
Container `p2s85` retained. Once 8.5.x receives the fix (scheduled 14:00 UTC today), rerun `parity_run.sh` against the patched build to verify the fix closes the orphan path.
---

## 6. Bottom line for the dossier

- **Do not rely on the public PoC "not working" as evidence of safety.** The underlying UAF is real, reproduced, and persists per-worker — it just needs private weaponization to reach RCE.
- **The three config controls we validated are genuinely effective** at removing the documented vulnerable path; the surest fix remains patching to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 when released.
- Detection should be deployed **now**: the log-based signals in §5 are already firing in our lab traffic and require no exploit success to be useful.
