/*
    php2shell — YARA rules for CVE-2026-109618 / CVE-2026-109619
    ============================================================================

    Two rule families:

      (a) Exploit tooling on disk — the public PoC scripts and the circulating
          "PoC bundle" archives. These are FILE/MEMORY hunt rules for IR and
          for scanning uploaded/extracted archives, not wire detections.

      (b) Weaponized session files — on-disk artifacts of Chains A/C, where the
          PHP session file *is* the payload drop. Session files are the most
          durable evidence of a successful or attempted chain; they survive
          worker restarts and are usually missed by web logs.

    Correlate with the WAF rules in ../modsecurity/php2shell-v2.conf and the
    network rules in the original package (handoff/.../detections/).

    HASH CONTEXT (hash-verified against the local intel corpus):
      skeleton standalone exploit (codepastes paste zzgsqk09h079300g,
      "php2shell-local", 560 lines):
        79dc151be410719025c80a417c8e6b67962085e6e5bac8352d124d102cfd9f3c
      jackalsyn PoC bundle archive:
        74adf2c4eb82776553837d185bae165494288747b43437fd452021a6ff6a93f0

    SAFETY: match-only. Nothing here executes or unpacks a sample. The
    circulating bundle and pastebin payloads are unvetted and may themselves
    be malicious — handle as hostile, analyse in a disposable lab only.

    Compiles with YARA 4.x (no imports, no external modules, no externals).
    Deploy examples at the bottom of this file.
*/

/* ==========================================================================
   FAMILY (a) — EXPLOIT TOOLING ON DISK
   ========================================================================== */

/*
   The full standalone Python exploit ("php2shell-local" / php2shell.py).
   It implements SEED -> PRIME -> TRIGGER -> LEAK -> RCE and necessarily
   contains the session-upload-progress trigger name, its private multipart
   boundary, and the PHP internals it forges. Four of eight strings keeps the
   rule resilient to variable renames while excluding the many research
   write-ups that mention only one or two of these terms.

   Note: "php_serialize_data" and "zend_call_function" also appear in
   legitimate PHP source trees and in analysis documents, hence the 4-of
   threshold and the 100 KB cap.
*/
rule PHP2Shell_Skeleton_Script : php2shell exploit_tooling CVE_2026_109618 CVE_2026_109619
{
    meta:
        description     = "Standalone php2shell exploit script (SEED/PRIME/TRIGGER/LEAK/RCE chain)"
        family          = "exploit_tooling"
        author          = "php2shell detection package v2"
        date            = "2026-10-21"
        reference       = "https://sansec.io/research/php2shell"
        reference_bundle = "codepastes.com paste zzgsqk09h079300g (php2shell-local, 560 lines)"
        hash_skeleton_sha256 = "79dc151be410719025c80a417c8e6b67962085e6e5bac8352d124d102cfd9f3c"
        confidence      = "high"
        tlp             = "WHITE"
        note            = "Matches 4+ of 8 chain-specific identifiers; file-size capped to avoid PHP source trees. Detailed write-ups that quote the code (e.g. an annex listing every function name) can also match: corroborate with the hash, sibling bundle rules, or the presence of executable logic."
    strings:
        $s1 = "PHP_SESSION_UPLOAD_PROGRESS"
        $s2 = "BGCTXBOUNDARY"
        $s3 = "zval_ptr_dtor"
        $s4 = "zend_call_function"
        $s5 = "forge_fcall_info"
        $s6 = "build_trigger_body"
        $s7 = "php_serialize_data"
        $s8 = "build_prime_body"
    condition:
        filesize < 100KB and
        4 of them
}

/*
   The jackalsyn-style PoC bundle: a shell reproducer plus the write-up and
   validation artifacts that ship beside it. The bundle is an archive, so this
   rule is intended for extracted files and for archive members (scan the
   unpacked tree). The two author handles ("C4b1NKr3W", "BrokenSec") are a
   strong provenance pair but are also visible in the public write-up, hence
   the 3-of threshold.
*/
rule PHP2Shell_Jackalsyn_Bundle : php2shell exploit_tooling CVE_2026_109618 CVE_2026_109619
{
    meta:
        description     = "jackalsyn/BrokenSec php2shell PoC bundle artifact (reproducer, notes, validation report)"
        family          = "exploit_tooling"
        author          = "php2shell detection package v2"
        date            = "2026-10-21"
        reference       = "https://sansec.io/research/php2shell"
        hash_bundle_sha256 = "74adf2c4eb82776553837d185bae165494288747b43437fd452021a6ff6a93f0"
        confidence      = "high"
        tlp             = "WHITE"
        note            = "3+ of 6 file/author markers; scan extracted bundle trees, not the .zip itself"
    strings:
        $b1 = "php2shell_repro.sh"
        $b2 = "ROOT_CAUSE.md"
        $b3 = "REPORT_VALIDATION.md"
        $b4 = "WEAPON_NOTES.md"
        $b5 = "C4b1NKr3W"
        $b6 = "BrokenSec"
    condition:
        filesize < 2MB and
        3 of them
}

/*
   Calif.IO "php2shell" tool artifacts. The leaked tool is not publicly hosted,
   so this rule hunts for remnants: shell history, copied banners, generated
   logs, notes, and re-packed copies. "PHP2SHELL" is matched ascii+wide and
   case-insensitively because the tool and its documentation use mixed case
   ("PHP2Shell"). The profile/banner strings come from the tool frame:
   --profile 21 / ubuntu2604-php85 and the adaptive worker-strategy banner.

   One string definition covers both encodings, so "2 of" means two distinct
   artifacts, not one artifact in two encodings.
*/
rule PHP2Shell_Calif_Tool_Artifacts : php2shell exploit_tooling CVE_2026_109618 CVE_2026_109619
{
    meta:
        description     = "Calif.IO PHP2Shell tool artifacts (banner, profile id, adaptive worker strategy)"
        family          = "exploit_tooling"
        author          = "php2shell detection package v2"
        date            = "2026-10-21"
        reference       = "https://sansec.io/research/php2shell"
        confidence      = "medium"
        tlp             = "WHITE"
        note            = "Hunts leaked-tool remnants (notes/logs/history), not a live binary; 2+ distinct markers"
    strings:
        $php2shell = "PHP2SHELL" ascii wide nocase
        $calif     = "Calif.IO" ascii wide nocase
        $profile   = "ubuntu2604-php85"
        $profile21 = "--profile 21"
        $strategy  = "worker strategy :: adaptive"
    condition:
        filesize < 5MB and
        2 of them
}

/*
   Generic session-upload-progress exploit research. Broader than the skeleton
   rule: catches rewrites, translated tooling, and write-ups that keep the
   root-cause vocabulary but renamed every function. Requires all three
   concept groups, which is rare in unrelated PHP documentation.
*/
rule PHP2Shell_Generic_Session_Exploit : php2shell exploit_tooling CVE_2026_109618 CVE_2026_109619
{
    meta:
        description     = "Generic php2shell session.upload_progress UAF exploit/research artifact"
        family          = "exploit_tooling"
        author          = "php2shell detection package v2"
        date            = "2026-10-21"
        reference       = "https://sansec.io/research/php2shell"
        reference_ghsa  = "GHSA-w8hw-w9fx-j79w / GHSA-6wmf-4rv5-p3rp"
        confidence      = "medium"
        tlp             = "WHITE"
        note            = "Requires session.upload_progress + UAF vocabulary + rfc1867/BG(serialize) internals"
    strings:
        $trigger  = "session.upload_progress" nocase
        $uaf1     = "use-after-free" nocase
        $uaf2     = /\bUAF\b/ nocase
        $intern1  = "php_session_rfc1867"
        $intern2  = "BG(serialize)"
    condition:
        filesize < 5MB and
        $trigger and
        any of ($uaf*) and
        any of ($intern*)
}

/* ==========================================================================
   FAMILY (b) — WEAPONIZED SESSION FILES (Chains A / C on-disk artifacts)
   ==========================================================================

   Background: PHP's rfc1867 upload-progress handler writes the client-supplied
   multipart filename verbatim into the session file. Chains A and C therefore
   leave PHP source or serialized objects inside sess_* files. A session file
   should contain ONLY serialized session variables — never a PHP open tag and
   never a bare object payload injected after a pipe.

   These rules are intentionally content-only. YARA cannot see the filename,
   so pair rule 2 with a deployment-side filename glob (see the deployment
   notes at the bottom).
   ========================================================================== */

/*
   Chain A (session-file injection -> LFI) and Chain C (handler mismatch).
   The session serialize prefix is either the php_serialize form "q0|s:..."
   (variable name + pipe) or "pad1|" as observed in the malformed/progress
   session shapes. If the file ALSO contains a PHP open tag or an object
   payload, the session has been weaponized.

   FP surface is small but non-zero: an application that stores user-supplied
   HTML/PHP source in a session variable can trip the "<?php" branch. Triage
   with the WAF rule that caught the upload and with the process/EDR signal.
*/
rule Webshell_In_Session_File : php2shell session_file webshell CVE_2026_109618 CVE_2026_109619
{
    meta:
        description     = "PHP session file containing PHP code or a serialized-object payload (Chain A/C drop)"
        family          = "weaponized_session"
        author          = "php2shell detection package v2"
        date            = "2026-10-21"
        reference       = "https://sansec.io/research/php2shell"
        confidence      = "high"
        tlp             = "WHITE"
        note            = "Session variables must never contain PHP tags or raw O:/R: object payloads"
    strings:
        $sess_a = "q0|s:"
        $sess_b = "pad1|"
        $php1   = "<?php"
        $php2   = "<?="
        $obj    = /(^|[|;])O:[0-9]{1,4}:"[A-Za-z_\\]/
        /* A real session file never starts with an interpreter shebang. This
           keeps the rule from matching exploit scripts and write-ups that
           quote the session payload literals in their own source. */
        $script = /^#!\/(usr\/bin\/env |usr\/bin\/|bin\/)(python|bash|sh|perl|ruby|node)/
    condition:
        filesize < 100MB and
        not $script at 0 and
        any of ($sess*) and
        any of ($php1, $php2, $obj)
}

/*
   Oversized session file.

   YARA has no filename predicate, so "matches sess_*" CANNOT be expressed
   here. This rule therefore matches on size + shape only and MUST be paired
   with a deployment-side filename filter, for example:

       find /var/lib/php/sessions -type f -name 'sess_*' -size +512k \
         -exec yara -w -r /etc/yara/php2shell.yar {} \;

   or, with a wrapper that renames/symlinks candidates into a staging tree,
   scan only that tree. Running this rule over an arbitrary filesystem will
   produce large-archive/log noise; the magic-byte exclusions below only
   remove the obvious non-session formats.

   A legitimate session can exceed 512 KB (large carts, imported state), so
   treat a hit as a hunt lead: check creation time against the upload window,
   the embedded PHP/object content (rule above), and the owning app.
*/
rule Oversized_Session_File : php2shell session_file hunt CVE_2026_109619
{
    meta:
        description     = "Session-shaped file > 512 KB (hunt lead; requires sess_* filename glob in deployment)"
        family          = "weaponized_session"
        author          = "php2shell detection package v2"
        date            = "2026-10-21"
        reference       = "https://sansec.io/research/php2shell"
        confidence      = "low"
        tlp             = "WHITE"
        note            = "YARA cannot match filenames; run only against sess_* via find/glob. Magic-less + session prefix checks reduce noise"
        deployment      = "find <save_path> -type f -name 'sess_*' -size +512k -exec yara ... {} +"
    strings:
        /* Serialized session data normally starts with a var name + '|' or
           directly with a serializer token. Anchor the token at offset 0. */
        $sess_start = /^([A-Za-z0-9_]{1,64}\|)?(a|s|i|b|d|O|N|R):/
        $sep_s = "|s:"
        $sep_a = "|a:"
        $sep_i = "|i:"
        $sep_O = "|O:"
    condition:
        filesize > 512KB and
        /* Exclude common container/executable formats. A real sess_* file is
           magic-less; this keeps a whole-filesystem scan from drowning. */
        not (
            uint32(0) == 0x7F454C46 or   /* ELF              */
            uint16(0) == 0x4D5A       or /* PE/COFF "MZ"     */
            uint32(0) == 0x504B0304   or /* ZIP / JAR / docx */
            uint16(0) == 0x1F8B       or /* gzip             */
            uint16(0) == 0x425A       or /* bzip2            */
            uint32(0) == 0xFD377A58   or /* xz               */
            uint32(0) == 0x377ABCAF   or /* 7-Zip            */
            uint32(0) == 0x52617221   or /* RAR              */
            uint32(0) == 0x25504446   or /* PDF "%PDF"       */
            uint32(0) == 0x89504E47   or /* PNG              */
            uint16(0) == 0xFFD8       or /* JPEG             */
            uint32(0) == 0x47494638   or /* GIF              */
            uint32(0) == 0x53514C69   or /* SQLite           */
            uint32(0) == 0xFEEDFACE   or /* Mach-O 32        */
            uint32(0) == 0xFEEDFACF   or /* Mach-O 64        */
            uint32(0) == 0xCAFEBABE   or /* Java class/fat   */
            uint32(0) == 0x0061736D      /* WebAssembly      */
        ) and
        (
            $sess_start at 0 or
            1 of ($sep*)
        )
}

/*
   Handler-mismatch residue (Chain C, and the cross-FPM-request serializer
   leak in primitive 3). A single session file that contains BOTH a fixed-width
   php-handler string ("s:39:\"N0...") and a raw object payload is the
   signature of two handlers writing/reading the same session file with
   different serializers — the exact condition Chain C converts into
   __destruct -> POP-chain RCE.

   The N0 anchor is the groom string observed in the circulating tooling; it
   is a length-prefixed string beginning "N0". Keep it: it discriminates this
   residue from an ordinary app that legitimately stores one object.
*/
rule Session_Serialize_Mismatch_Residue : php2shell session_file CVE_2026_109619
{
    meta:
        description     = "Session file mixing php-handler serialized strings with php_serialize object payloads (handler mismatch)"
        family          = "weaponized_session"
        author          = "php2shell detection package v2"
        date            = "2026-10-21"
        reference       = "https://sansec.io/research/php2shell"
        reference_ghsa  = "GHSA-6wmf-4rv5-p3rp"
        confidence      = "medium"
        tlp             = "WHITE"
        note            = "Same file written/read under different session.serialize_handler values (php vs php_serialize)"
    strings:
        $ser_str = /s:[0-9]{1,6}:"N0/
        $obj     = /(^|[|;])O:[0-9]{1,4}:"[A-Za-z_\\]/
        $ref     = /(^|[|;])R:[0-9]{1,6};/
    condition:
        filesize < 100MB and
        $ser_str and
        ($obj or $ref)
}

/* ==========================================================================
   DEPLOYMENT NOTES

   1. Scan the filesystem (host agent, cron, or IR triage):

        yara -r -w /etc/yara/php2shell.yar /var/www /tmp /var/lib/php/sessions

      (-w suppresses warnings on unreadable files; -r recurses.)

   2. Oversized_Session_File needs the filename filter that YARA lacks:

        find /var/lib/php/sessions -type f -name 'sess_*' -size +512k \
          -print0 | xargs -0 -r yara -w /etc/yara/php2shell.yar

      If your distro's YARA supports the `-g`/`--print-tags` flag, add it to
      route hits by family tag. There is no native filename condition in
      YARA 4.x; do not remove this wrapper and expect useful results.

   3. Scan extracted PoC bundles, not the archives:

        unzip -q bundle.zip -d /tmp/bundle && yara -r php2shell.yar /tmp/bundle

      Archive scanning requires the `zip`/`tar` modules and is deliberately
      left out so the rule file stays dependency-free.

   4. Session-file rules read attacker-controlled content. Never open a hit
      with a PHP interpreter, and never `include` a hit. Treat it as evidence:
      hash it, copy it, then analyse the bytes with `xxd`/`strings`.

   5. False-positive tuning: if an application legitimately serializes
      objects into sessions, exclude its save_path from
      Webshell_In_Session_File / Session_Serialize_Mismatch_Residue via
      separate scan roots rather than weakening the content conditions.
   ========================================================================== */