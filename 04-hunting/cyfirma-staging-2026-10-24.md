# CYFIRMA staging advisory — suspected source infrastructure (24 Oct 2026)

**Compiled:** 2026-10-30 from the CYFIRMA research page `cyfirma-threat-advisory-suspected-dprk-campaign-
staging-php2shell-targeting-against-global-php-infrastructure` (advisory quote **CYF-EWR-2026-1022-PHP2SHELL-DPRK**,
re-issued 24 Oct). **Suspected infrastructure only, CYFIRMA's assessment, not independently verified by us.**
CYFIRMA labels the addresses **BLOCK / MONITOR**. Defanged here.

## Why this matters

This fills the gap our earlier CYFIRMA coverage flagged: we had the assessment (216-host target set, suspected
DPRK/Lazarus staging) but no indicators. The advisory now carries a **suspected source/staging address list**,
an updated indicator count (**21 scan-node addresses added; 17 Version 2 addresses and 15 staging addresses
remain valid**), request-body hashes, and operator tradecraft from a closed I2P channel. It is a **staging and
scanning** set, not a confirmed exploitation list.

## Suspected source / scan / staging addresses

Treat as **block or monitor**, subject to local false-positive checks. Some may be compromised third-party
hosts or proxy egress rather than attacker-owned.

`103.114.163[.]188`, `103.216.220[.]92`, `109.71.252[.]97`, `112.245.227[.]143`, `117.83.155[.]42`,
`118.186.18[.]243`, `119.59.101[.]74`, `134.209.159[.]64`, `138.199.43[.]94`, `141.98.255[.]246`,
`152.237.230[.]31`, `152.237.230[.]36`, `156.225.28[.]97`, `161.97.178[.]84`, `161.97.179[.]152`,
`178.249.214[.]6`, `185.177.72[.]45`, `186.22.19[.]172`, `2.59.133[.]151`, `223.178.86[.]187`,
`23.234.113[.]169`, `31.223.184[.]166`, `32.236.50[.]30`, `32.236.55[.]80`, `37.19.200[.]5`,
`45.198.224[.]169`, `47.250.155[.]133`, `5.255.114[.]109`, `64.11.92[.]102`, `79.193.197[.]168`,
`85.11.167[.]243`, `85.11.190[.]112`, `92.118.112[.]100`, `95.179.220[.]151`, `95.217.98[.]37`

**Overlap with our other sources:** `92.118.112[.]100` is the Potassium loader host; `45.198.224[.]169` and
`85.11.167[.]243` appear as attack sources in the Wiz/Arctic Wolf reporting; `118.186.18[.]243` is in the
broader scan set. Cross-source overlap raises confidence in those individual addresses, but they may still be
compromised infrastructure.

## Hashes (as published)

| SHA-256 | Note |
|---|---|
| `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` | also listed by Arctic Wolf as Potassium ARM payload |
| `c29295420ae51592fbf97bd6050c16e002e3c7ecd4e824f7217f9244bfef7e1d` | CYFIRMA indicator set |
| `43898a0a53bbd25d31ad9f5018ed3182be98a66109b22c9cab545a9fc447992a` | CYFIRMA indicator set |
| `7bc41ed79a9ae909927a9e40701736460a8cb70fca16ce1510e58677aca764b6` | CYFIRMA indicator set |

**Important caveat from the advisory:** some hashes are **of HTTP request bodies, not files**. A body hash only
matches a byte-for-byte capture (PCAP, WAF or proxy); changing boundary or field values changes the hash. Use
the `.user.ini`/file-size alternative where offered rather than treating body hashes as file IOCs.

## Tradecraft described (useful for hunting, not for blocking)

- **Node rotation and burn discipline:** addresses that show filtering or rate-limiting are marked, pulled
  from the active set and not reused.
- **Low-and-slow pacing** across infrastructure, with separation between scanning and staging hosts.
- Closed **I2P channel** operators discussed the target list, country split, and "plenty of infrastructure
  providers, telco, government and bank ranges"; CYFIRMA says the target set was claimed at **581 hosts,
  expanded from the original 216** across 10 countries (adversary claim).
- Operator handles are redacted in the advisory.

## Suggested hunt

```spl
(index=proxy OR index=firewall OR index=web)
| search (src_ip IN ("103.114.163.188","103.216.220.92","109.71.252.97","112.245.227.143","117.83.155.42",
   "118.186.18.243","119.59.101.74","134.209.159.64","138.199.43.94","141.98.255.246","152.237.230.31",
   "152.237.230.36","156.225.28.97","161.97.178.84","161.97.179.152","178.249.214.6","185.177.72.45",
   "186.22.19.172","2.59.133.151","223.178.86.187","23.234.113.169","31.223.184.166","32.236.50.30",
   "32.236.55.80","37.19.200.5","45.198.224.169","47.250.155.133","5.255.114.109","64.11.92.102",
   "79.193.197.168","85.11.167.243","85.11.190.112","92.118.112.100","95.179.220.151","95.217.98.37"))
| search (url="*PHP_SESSION_UPLOAD_PROGRESS*" OR http_user_agent IN ("php2shell-scan/109618",
   "php2shell-test/2.0.0") OR status=200)
| stats count min(_time) max(_time) values(url) by src_ip, http_user_agent
```

Prioritise any address that both **scanned** and later **succeeded** against a PHP endpoint. Scanning alone is
noise on the modern internet.

## Caveats

- CYFIRMA's assessment is **suspected**, based on a closed-channel source plus infrastructure correlation. We
  have not verified attribution or that every address is attacker-controlled.
- Staging infrastructure rotates; the advisory itself says 21 new scan nodes were added and others retired.
  Pull the DeCYFIR IOC set or re-check the advisory before operational blocking.
- Do not treat scanning as compromise. These indicators support triage and blocking decisions, not incident
  conclusions.
