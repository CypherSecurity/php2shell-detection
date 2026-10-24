##! php2shell — Zeek detection policy (CVE-2026-109618 / CVE-2026-109619)
##!
##! Companion to detections-v2/suricata/php2shell-v2.rules. This is a *new-package*
##! script: it loads only base Zeek scripts (http analyzer + notice + files
##! frameworks), no zkg packages, and uses only long-stable APIs.
##!
##! Requires Zeek >= 4.2 (5-argument http_request signature, to_lower(), and the
##! base http analyzer exposing raw request entity data via http_entity_data).
##!
##! What it watches for (all three are lab-validated shapes from 2026-10-21):
##!
##!   (a) Multipart request body containing BOTH `PHP_SESSION_UPLOAD_PROGRESS` and a
##!       `name="PHPSESSID"` form field. That pair is the SEED stage: the attacker
##!       claims the session id from the body (session fixation) and arms the
##!       upload-progress callback. A progress field alone occurs in benign upload
##!       forms, and a PHPSESSID *cookie* is of course normal — the combination of
##!       the upload-progress field plus PHPSESSID as a *form field* is the signal.
##!
##!   (b) A ~1-2 second stall between body chunks of a multipart request. The arm
##!       body is written slowly, mid-body, to line up with
##!       session.upload_progress.min_freq / the progress callback timing. This is a
##!       timing heuristic: one slow chunk is not evidence (mobile clients, TCP
##!       backpressure and proxies all stall). It is reported once per request, and
##!       you should only page on it when it co-occurs with (a) or (c).
##!
##!   (c) More than 100 multipart parts in one request. The validated fire body uses
##!       150 x name="s[]" + 600 x name="t[]" parts; 100+ parts is already outside
##!       normal form behaviour (normal forms: single digits, large uploads: a
##!       handful of file parts).
##!
##! FP EXPECTATIONS
##!   (a) low — upload-progress UIs that also post a session id field exist (some
##!       PHP frameworks do it deliberately). Expect a trickle; whitelist by host.
##!   (b) medium-high standalone — only meaningful as corroboration.
##!   (c) very low — 100+ parts in one request is essentially always a spray.
##!
##! LIMITATIONS, stated deliberately:
##!   * Zeek's HTTP analyzer does not parse multipart part headers; we inspect the
##!     raw entity body in http_entity_data. A marker split across two TCP segments
##!     can be missed by the incremental counts (bodies are chunked at arbitrary
##!     sizes), so counts are lower bounds. Bodies are capped at body_cap.
##!   * A request body that is never fully delivered (client abort) produces no
##!     http_end_entity, so (a) is only evaluated on complete requests. The
##!     part-count (c) and stall (b) notices fire incrementally.
##!   * TLS is only covered if you feed Zeek decrypted traffic (SSLKEYLOG / tap).
##!   * This does not attempt to detect the OOM response itself; that is a
##!     Suricata/host-log job (see the paired rules file).

module php2shell;

@load base/protocols/http
@load base/frameworks/notice
# The files framework is loaded so file IDs / extraction remain available for
# enrichment on hosts that also enable Files:: extraction; the body heuristics below
# do not depend on it, which keeps the script usable with plain base Zeek.
@load base/frameworks/files

export {
    redef enum Notice::Type += {
        ## Multipart POST carrying PHP_SESSION_UPLOAD_PROGRESS plus a PHPSESSID
        ## form field — the SEED / session-fixation shape.
        Multipart_Upload_Progress,
        ## A ~1-2 s gap between body chunks inside a multipart request — mid-body
        ## stall used to hit session.upload_progress.min_freq timing (arm stage).
        Multipart_Midbody_Stall,
        ## More than part_flood_threshold multipart parts in a single request —
        ## the s[]/t[] spray shape.
        Multipart_Part_Flood,
    };

    ## Parts per request above which we raise Multipart_Part_Flood.
    ## Lab fire body: 150 s[] + 600 t[] + 2 file parts. Tune up if you have
    ## legitimate >100-part forms (some ticketing/CMDB apps do).
    const part_flood_threshold: count = 100 &redef;

    ## A "stall" is a gap in [stall_min, stall_max] between request-body chunks.
    ## The lab-validated stall is ~1-2 s; the window is deliberately generous on the
    ## upper end to survive timer coarse-ness and scheduler jitter.
    const stall_min: interval = 1sec &redef;
    const stall_max: interval = 2500msec &redef;

    ## Number of qualifying stalls within one request before we notice.
    const stall_gaps_to_notice: count = 2 &redef;

    ## Maximum request body we retain for the string checks (2 MB, matching the
    ## Suricata request-body-limit in the companion rules file). The lab arm body
    ## with a 1.8 MB filename fits; larger bodies are truncated for matching only.
    const body_cap: count = 2 * 1024 * 1024 &redef;

    ## Per-request state. Reset at every http_request, so one Info instance tracks
    ## exactly one request/response exchange on the connection.
    type Info: record {
        method:         string  &default="";
        uri:            string  &default="";
        multipart:      bool    &default=F;
        body:           string  &default="";
        parts:          count   &default=0;
        ## Only set once the first body chunk has been seen; read only when
        ## seen_chunk is T, so no synthetic 0sec default is needed.
        last_chunk:     time    &optional;
        seen_chunk:     bool    &default=F;
        stall_gaps:     count   &default=0;
        stall_noticed:  bool    &default=F;
        parts_noticed:  bool    &default=F;
        progress_noticed: bool  &default=F;
    };
}

redef record connection += {
    php2shell: Info &optional;
};

# -------------------------------------------------------------------------------------
# Per-request reset. http_request fires once, when the request headers are complete
# and before any body bytes, so this is the natural place to start a new tracking
# record (connections may be keep-alive with many requests).
# -------------------------------------------------------------------------------------
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    c$php2shell = Info();
    c$php2shell$method = method;
    c$php2shell$uri = original_URI;
    }

# -------------------------------------------------------------------------------------
# Multipart-ness comes from the Content-Type request header. Zeek normalises header
# case in practice, but to_lower() keeps this independent of analyzer version.
# -------------------------------------------------------------------------------------
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig )
        return;

    if ( ! c?$php2shell )
        return;

    if ( to_lower(name) == "content-type" && /multipart\/form-data/ in to_lower(value) )
        c$php2shell$multipart = T;
    }

# -------------------------------------------------------------------------------------
# Body inspection. http_entity_data is emitted for every delivered chunk of the HTTP
# message body, request direction included. We only look at request bodies, and only
# for multipart requests — that keeps the per-chunk work off the hot path for normal
# GET/POST traffic.
# -------------------------------------------------------------------------------------
event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! is_orig )
        return;

    if ( ! c?$php2shell || ! c$php2shell$multipart )
        return;

    # -- (b) inter-chunk timing ------------------------------------------------
    # network_time() is packet time (not wall clock), which is what we want for a
    # wire-timing heuristic. The first chunk has no predecessor, hence seen_chunk.
    local now = network_time();

    if ( c$php2shell$seen_chunk )
        {
        local gap = now - c$php2shell$last_chunk;

        if ( gap >= stall_min && gap <= stall_max )
            {
            c$php2shell$stall_gaps = c$php2shell$stall_gaps + 1;

            if ( ! c$php2shell$stall_noticed &&
                 c$php2shell$stall_gaps >= stall_gaps_to_notice )
                {
                c$php2shell$stall_noticed = T;
                NOTICE([$note=Multipart_Midbody_Stall,
                        $msg=fmt("php2shell: %d mid-body stall(s) of 1-2.5s in multipart request body", c$php2shell$stall_gaps),
                        $sub=fmt("%s %s (%d qualifying gaps)", c$php2shell$method, c$php2shell$uri, c$php2shell$stall_gaps),
                        $conn=c,
                        $identifier=cat(c$id$orig_h, "-", c$php2shell$uri)]);
                }
            }
        }

    c$php2shell$last_chunk = now;
    c$php2shell$seen_chunk = T;

    # -- body retention (capped) ----------------------------------------------
    if ( |c$php2shell$body| < body_cap )
        c$php2shell$body += data;

    # -- (c) part counting -----------------------------------------------------
    # Count Content-Disposition occurrences per chunk via split_string. Markers that
    # straddle a chunk boundary are missed, so this is a lower bound; for the spray
    # bodies the marker appears hundreds of times and the drift is irrelevant.
    local segs = split_string(data, /Content-Disposition/);

    if ( |segs| > 1 )
        c$php2shell$parts += |segs| - 1;

    if ( ! c$php2shell$parts_noticed &&
         c$php2shell$parts > part_flood_threshold )
        {
        c$php2shell$parts_noticed = T;
        NOTICE([$note=Multipart_Part_Flood,
                $msg=fmt("php2shell: multipart part flood, %d parts in one request (>%d)", c$php2shell$parts, part_flood_threshold),
                $sub=fmt("%s %s", c$php2shell$method, c$php2shell$uri),
                $conn=c,
                $identifier=cat(c$id$orig_h, "-", c$php2shell$uri)]);
        }
    }

# -------------------------------------------------------------------------------------
# End of a request body. (a) needs the COMPLETE body because the PHPSESSID form field
# can appear before or after the progress field, so evaluate it here rather than
# per-chunk. Only the request direction is interesting.
# -------------------------------------------------------------------------------------
event http_end_entity(c: connection, is_orig: bool)
    {
    if ( ! is_orig )
        return;

    if ( ! c?$php2shell || ! c$php2shell$multipart )
        return;

    if ( c$php2shell$progress_noticed )
        return;

    # strstr returns the 1-based position, or 0 when absent.
    local has_progress = ( strstr(c$php2shell$body, "PHP_SESSION_UPLOAD_PROGRESS") > 0 );
    local has_sessid_field = ( strstr(c$php2shell$body, "name=\"PHPSESSID\"") > 0 );

    if ( has_progress && has_sessid_field )
        {
        c$php2shell$progress_noticed = T;
        NOTICE([$note=Multipart_Upload_Progress,
                $msg="php2shell: multipart body has PHP_SESSION_UPLOAD_PROGRESS and a PHPSESSID form field (session fixation / SEED shape)",
                $sub=fmt("%s %s, %d parts", c$php2shell$method, c$php2shell$uri, c$php2shell$parts),
                $conn=c,
                $identifier=cat(c$id$orig_h, "-", c$php2shell$uri)]);
        }
    }