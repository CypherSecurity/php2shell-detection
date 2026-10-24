# Leak-stage boundary analysis (21 Oct 2026, ~14:40 UTC)

## State achieved
- Chain runs end-to-end deterministically: seed → prime(500) → trigger(200), 6/6 clean
  with fresh-worker-per-attempt (flock-deadlock workaround per WEAPON_NOTES receipt 3).
- All static artifacts validated against ground truth (see VALIDATION-REPORT §7):
  struct offsets via offsetof probe against real 8.5.4 headers; per-build symbol
  profile from build-id-matched ddebs; zif_system = dtor − 0x20B6B0, call = dtor − 0xBE3F0
  (delta reproduces the video's leaked pointer pair byte-for-byte).

## What does not reproduce
- pad1 array corruption (integer-keyed pointer entries in the session file) — 0/6 with
  corrected 64-bin grooms (39-byte values), 0/8 with the skeleton's original 15-byte
  grooms (which target the wrong size class: 24+15+1=40B vs the _emalloc_64 context).

## Root-cause assessment (why this is the real wall)
1. The corruption requires the freed 64-byte php_serialize_data block to be reclaimed
   by a groom string AND the stale context's embedded HashTable (arData at +16) to be
   redirected into attacker-readable state such that php_add_var_hash's inserts land
   in the session tree being serialized. That needs specific heap adjacency:
   the reclaimed block must BE the context the trigger request reuses, and the
   session tree arrays must sit at addresses the fake arData points into.
2. glibc dependence: author's own receipts — full chain worked only with
   "glibc heap grooming -> php85 aligned495" on glibc 2.39 (Ubuntu 26.04);
   FAILED on Debian 12/glibc 2.36. This lab runs glibc 2.43 (26.04 current patch),
   where tcache/bin behavior has again shifted. The groom offsets are not portable
   across glibc point releases.
3. The video tool's "aligned495" / "compact natural_tables=149" / "compact table
   write phase=580/600" stages are precisely this grooming — private, per-build,
   per-glibc tuning that neither public PoC ships as working code.

## What WOULD close the gap (for future continuation)
- Instrument _emalloc_64 returns during the trigger request (gdb catch-point or
  LD_PRELOAD malloc interposer) to observe which allocation actually reclaims the
  freed context block — then tune groom count/length/order to win that race.
- Match glibc exactly: ubuntu:26.04 image at the October 2025 package snapshot
  (glibc 2.39-0ubuntu8.x), not current patches.
- Use php_var_serialize_init breakpoint (already proven in receipt_experiment.sh)
  to confirm level!=0 reuse fires in the same attempt as the groom, before expecting
  pad1 corruption.

## Detection takeaway (the actual goal)
Even without leak/RCE reproduction, exploit-internal artifacts validated for detection:
- profile math: zif_system/call = f(leaked dtor) per build — detections should not
  assume fixed addresses.
- corruption artifacts in logs: 'zend_mm_heap corrupted' (SIGABRT), dangling
  PS(save_path) strings embedding old log text, 'Cannot encode non-existent session',
  zombie worker piles after multipart bursts (12 zombies observed).
