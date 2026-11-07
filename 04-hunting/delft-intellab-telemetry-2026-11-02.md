# TU Delft live telemetry — what php2shell exploitation actually looks like

**Source:** Delft Threat Intelligence Lab (TU Delft), "PHP2Shell in the wild",
`https://php2shell.delftintellab.com/` — honeypots and network telescope, data since 20 October 2026,
refreshed every 5 minutes. Page last updated at the time of capture: **2026-11-02 10:12:10 UTC**.
**Status:** independent research telemetry, **not verified by us**. The page's own traffic is excluded and
its sensor addresses are replaced with `<sensor>`. Figures move as the page refreshes; treat the values below
as a snapshot, not a fixed total.

## Why this source matters

Our own honeypot work covered 35 shells from 72 sources on one weekend. This is a much larger and more
continuous view of the same phenomenon, from a national research lab, and it separates **attempts** from
**delivery** and from **code execution**. It also names the delivery hosts, which is what detection teams
need, not just source IPs.

## Key numbers at capture

| Metric | Value |
|---|---|
| Exploitation requests | **83,038** |
| Source IPs | **787** |
| Autonomous systems | 330 |
| Countries | 73 |
| Window | 2026-10-21 08:37:17 to 2026-11-02 10:08:07 UTC |
| Source IPs that sent code or a dropper | **181** |
| Requests sent before the 21 Oct fixed releases | 49 from 2 IPs |
| Distinct multipart boundaries | 819 |
| Sensor addresses hit | 2,727 |
| Busiest hour | 2026-10-26 14:00 UTC, 8,179 requests |

## Funnel: how far attempts get

| Step | Requests | Source IPs |
|---|---:|---:|
| Probe | 61,797 | 672 |
| Code execution | 10,597 | 154 |
| Overload (OOM stage) | 5,916 | 152 |
| Dropper | 4,728 | 51 |

So of 787 source IPs, about **one in four** reached code execution, and about **one in fifteen** reached a
dropper. That ratio, from a much bigger dataset than ours, is consistent with our reading that the exploit is
environment-sensitive: most attempts fail, the ones that land go straight to payload retrieval.

## Techniques and first sightings (21 October)

| Time (UTC) | First |
|---|---|
| 08:37:17 | request resembling PHP2Shell (network telescope) |
| 13:00:12 | request on the high-interaction honeypot |
| 13:25:25 | first OS command, first PHP code in filename |
| 13:42:29 | first UAF: forged zval structs |
| 14:20:28 | first request after the fix; first tool naming itself in the user agent |
| 14:25:31 | first `wget`/`curl` dropper |
| 15:01:07 | first session deserialization gadget |
| 15:38:33 | first PHP code in the progress field |
| 16:13:51 | first OOM: deeply nested names; empty file fields |
| 18:35:15 | first OOM: header-line flood |
| 18:36:14 | first OOM: hundreds of parts |
| 19:26:35 | first request against a partner honeypot |
| 22:15:14 | first body of 1 MB or more |

Technique counts include: probe only 61,797/672 IPs; OS command 11,110/66; PHP code in progress field
10,479/36; session deserialization gadget 1,324/109; OOM hundreds of parts 1,824/95; wget/curl dropper
4,728/51; UAF forged zval structs 1,837/11.

## Delivery indicators observed (defanged; do not fetch)

| URL | Requests / IPs |
|---|---|
| `hxxp://45.74.7[.]227/collect/p2srun.php?w=p2s<sensor>` | 159 / 16 |
| `hxxp://45.74.7[.]227/collect/p2srun.php?...&stage=diag...` | 76 and 83 / 13 and 12 |
| `hxxp://176.65.139[.]153/wget.sh` | 17 / 6 |
| `hxxps://217.60.102[.]5/sh` | 3,561 / 4 |
| `hxxps://pastebin[.]com/raw/wCYGVCBG` | 71 / 2 |
| `hxxp://92.118.112[.]100/p` | 70 / 2 |
| `hxxp://92.118.112[.]100/s` | 572 / 1 |
| `hxxp://92.118.112[.]100/nfs` | 7 / 1 |
| `hxxps://webhook[.]site/c8370342-2a5c-489c-a0d3-35930cc2bc54/<id>` | 2 each / 2 |
| `hxxps://webhook[.]site/0e7f04d6-7839-40d6-963e-a6d7744a4cd3` | 23 / 1 |
| `hxxp://217.15.162[.]38:27182/<token>/srl.sh` | 93 / 1 |
| `hxxp://217.15.162[.]38:27182/DT14REn1ylaykdkWBqbML5wf/issue` | 93 / 1 |
| `hxxp://134.209.89[.]212/p` | 65 / 1 |
| `hxxp://87.251.64[.]204:7716/i` | 29 / 1 |
| `hxxp://185.225.191[.]232/c` | 21 / 1 |
| `hxxp://191.217.250[.]227:8081/b.php?w=p2s<sensor>` | 14 / 1 |
| `hxxp://45.115.26[.]26:8000/cCmono` and `/cClar` | 5 each / 1 |
| `hxxp://hana[.]by/` | 2 / 1 |

Note: `92.118.112[.]100` is the same loader host named in the Potassium Mirai reporting (see
`potassium-botnet-php2shell-2026-10-28.md`). This source adds `/p`, `/s` and `/nfs` paths on that host and
shows it serving multiple campaigns, so block the host and paths, not just one URI.

## Malware samples named at capture

| Sample | SHA-256 (prefix) | Notes |
|---|---|---|
| `nfs` (Mirai-derived DDoS bot) | `0c5486f06620e26e…` | encrypted C2; resolves C2 by domain and Ethereum ENS fallback. Matches the Potassium sample hash we already carry |
| `x86_64(2)` (Mirai "2.0.4_socks5") | `7d9965deae0d3d98…` | domain lookup failed in sandbox, used live fallback C2 which accepted the bot but sent no attack command |
| `cb` (Nim implant "crong3-agent", 3.0.0-929, poses as "sysmon") | `a5289abece66fbaf…` | persistence; C2 from Ethereum ENS and Solana account; never uses normal DNS resolver |
| `f0aa…` (unidentified) | `f0aa83bbbd2c75e2…` | DNS-over-TLS lookup then one encrypted message to a silent server |

## Networks most active (requests / source IPs)

AS137409 GSL Networks US 3,796/57 · AS21859 Zenlayer PT 2,671/51 · AS211680 Sistemas Informaticos PT
3,792/42 · AS206092 F.n.s. Holdings US 120/38 · AS212238 Datacamp CA 1,889/27 · AS9009 M247 Europe TW
13,822/25 · AS14061 DigitalOcean AU 1,009/12 · AS39351 31173 Services AB NL 933/10 · AS13335 Cloudflare SG
141/10 · AS219502 Storm Industries DE 135/10 · AS215125 Church of Cyberology NL 51/9.

Most of these are hosting or proxy providers, which is expected for commodity scanning and for the
anonymisation layer. **AS presence is not attribution**; rented hosts are routinely used by multiple actors.

## How to hunt with it

1. Proxy/egress logs: any request from a PHP server to `45.74.7[.]227`, `176.65.139[.]153`,
   `217.60.102[.]5`, `217.15.162[.]38:27182`, `134.209.89[.]212`, `87.251.64[.]204`,
   `185.225.191[.]232`, `191.217.250[.]227:8081`, `45.115.26[.]26:8000`, `92.118.112[.]100`, or
   `pastebin.com/raw/wCYGVCBG`. These are *delivery* indicators; a hit means code was already running.
2. Web logs: POST bodies containing `p2srun`, `wget.sh`, `srl.sh`, or a 36-character UUID from the
   webhook.site list above.
3. Host: look for outbound `curl`/`wget` spawned by the PHP worker (Suricata/Sigma rules cover the
   process and parent-shape, not just the URL).
4. Treat a delivery-only hit as **compromised**, not as a blocked attempt. The dropper runs after code
   execution.

## Caveats

- **Snapshot values, and totals are "as of the page's data window end", not live.** The page re-renders
  every five minutes, but the lab ingests in batches with pauses: on 3 November the data window froze at
  10:17 UTC for about 4.5 hours and again from 20:07 UTC, while the refresh timestamp kept advancing. A
  flat total therefore means *missing data*, not a quiet network. Read the stated window end (for example
  "2026-10-21 08:37:17 to 2026-11-03 20:07:00 UTC") before drawing any trend conclusion. On recovery the
  backlog lands in one hour (observed: +338 and +210 catch-up hours), so a post-outage jump with a flat
  source count is backfill, not a surge.
- Research telescope data includes opportunistic scanning that resembles PHP2Shell without being it.
  The page's own "first request resembling" wording acknowledges this.
- Sensor placeholders (`<sensor>`) mean URLs in the source are not literal; we reproduce them with the
  placeholder intact.
- We have not independently validated the malware hashes or the C2 claims. Hashes are for triage and
  blocking decisions, and the `nfs` hash matches an independently reported sample.
- **Coverage gap, measured and closed:** the data window stalled at **2026-11-04 21:10:31 UTC** and did not
  advance for **~40.4 h**. It resumed at **2026-11-06 13:36:20 UTC**, with the total moving only from 85,521
  to **85,525 (+4)** while source IPs (798) and code-or-dropper senders (181) stayed flat. Two readings fit
  that increment and this page cannot separate them: the interval simply carried almost no traffic, or the
  long outage was never replayed (earlier, shorter stalls *were* replayed, in one-hour jumps of +338, +210,
  +78 and +370). **Do not present the +4 as evidence of a quiet network, and do not present it as evidence
  of a drop either.** Treat the pre-gap funnel and per-ASN figures as **as of 2026-11-04 21:10 UTC**.

- **Second coverage gap, measured and closed:** after the series resumed on 6 Nov, the data window stalled
  again at **2026-11-06 19:33:53 UTC** and did not advance for **16 h 26 min**. It resumed at
  **2026-11-07 12:00:06 UTC**, with the total moving from 85,982 to **86,018 (+36)**, source IPs from 798 to
  **799 (+1)** and code-or-dropper senders from 181 to **182 (+1)**. Unlike the 40 h gap, this one did produce
  a small increment, but +36 across 16.4 h is a fraction of the rate seen while the window was advancing
  normally, so the interval is only partly covered. Treat pre-12:00 figures as of the 6 Nov 19:33 cutoff and
  do not read either flat period as a quiet network.
