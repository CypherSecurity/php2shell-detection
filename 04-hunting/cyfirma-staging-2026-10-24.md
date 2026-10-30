# CYFIRMA staging advisory — versioned IOC sets (V1–V4, 22–29 Oct 2026)

**Compiled:** 2026-10-30, after the CYFIRMA research page was restructured into four dated versions
(`cyfirma-threat-advisory-suspected-dprk-campaign-staging-php2shell-targeting-against-global-php-infrastructure`,
quote **CYF-EWR-2026-1022-PHP2SHELL-DPRK**). **Suspected infrastructure, CYFIRMA's assessment, not independently
verified by us.** CYFIRMA labels the addresses **BLOCK / MONITOR**. Defanged here.

**Revision note:** the page changed during our watch. On 30 Oct it exposed **24 scan/staging addresses in a V4
(29 Oct) table**, plus the earlier **V3 (24 Oct, 21 addresses)**, **V2 (23 Oct, 17 addresses)** and **V1 (22 Oct,
27 addresses)** tables. An earlier capture of the same advisory listed a partly different set; this document
now follows the advisory's own versioning rather than a flattened list.

## Attribution update (V4, 29 Oct)

CYFIRMA's V4 bottom line now assesses the operators as **Korean-speaking, with high confidence North Korean
(DPRK) state-nexus, Lazarus Group ecosystem**, with a **dual financial and espionage mandate**. Earlier
versions said "suspected". The target set is claimed at **581 hosts, expanded from the original 216**, across
10 countries. This is CYFIRMA's assessment from intercepted closed-I2P-channel conversation plus open-source
telemetry; it is not corroborated by us.

## V4 — current scan and staging addresses (29 Oct)

`152.237.230[.]31`, `117.83.155[.]42`, `152.237.230[.]36`, `85.11.190[.]112`, `138.199.43[.]94`,
`23.234.113[.]169`, `118.186.18[.]243`, `2.59.133[.]151`, `141.98.255[.]246`, `156.225.28[.]97`,
`178.249.214[.]6`, `64.11.92[.]102`, `161.97.178[.]84`, `161.97.179[.]152`, `47.250.155[.]133`,
`186.22.19[.]172`, `119.59.101[.]74`, `185.177.72[.]45`, `32.236.50[.]30`, `32.236.55[.]80`,
`223.178.86[.]187`, `112.245.227[.]143`, `95.179.220[.]151`, `79.193.197[.]168`

## V3 — scan-node addresses (24 Oct, 21 addresses)

`142.93.155[.]162`, `134.122.38[.]73`, `5.255.114[.]109`, `165.22.232[.]198`, `159.223.59[.]200`,
`192.177.131[.]13`, `94.154.42[.]149`, `173.249.16[.]178`, `170.64.224[.]137`, `170.64.226[.]40`,
`45.148.10[.]80`, `152.237.230[.]29`, `146.70.194[.]93`, `185.157.109[.]60`, `143.246.213[.]138`,
`144.91.70[.]51`, `217.60.196[.]124`, `151.253.243[.]219`, `23.106.131[.]214`, `173.249.16[.]192`,
`45.148.10[.]201`

## V2 — source IPs (23 Oct, 17 addresses)

`102.207.250[.]188`, `94.154.43[.]185`, `75.119.143[.]189`, `117.203.73[.]63`, `146.190.107[.]103`,
`95.217.164[.]124`, `124.122.142[.]142`, `188.80.228[.]122`, `134.209.181[.]133`, `134.209.252[.]157`,
`119.63.72[.]54`, `138.68.161[.]170`, `95.216.5[.]90`, `103.21.161[.]105`, `115.96.27[.]126`,
`185.207.232[.]121`, `78.47.85[.]99`

## V1 — infrastructure and C2 (22 Oct, 27 addresses)

`146.70.114[.]180`, `146.70.114[.]182`, `147.175.149[.]67`, `147.78.168[.]57`, `109.56.219[.]150`,
`158.173.75[.]178`, `185.203.18[.]54`, `185.235.212[.]105`, `103.77.210[.]80`, `128.90.176[.]13`,
`138.199.34[.]201`, `145.255.150[.]25`, `149.102.232[.]44`, `149.102.232[.]93`, `158.173.242[.]133`,
`147.78.168[.]67`, `92.118.112[.]100`, `103.216.220[.]92`, `31.223.184[.]166`, `37.19.200[.]5`,
`134.209.159[.]64`, `103.114.163[.]188`, `95.217.98[.]37`, `85.11.167[.]243`, `45.198.224[.]169`,
`109.71.252[.]97`

**Overlaps worth noting:** `92.118.112[.]100` is the Potassium loader host, `45.198.224[.]169` and
`85.11.167[.]243` appear in Wiz/Arctic Wolf reporting, and `103.216.220[.]92`, `37.19.200[.]5`,
`103.114.163[.]188`, `95.217.98[.]37`, `109.71.252[.]97`, `31.223.184[.]166` recur across our other sources.

## Hashes

The earlier revision of the advisory listed four SHA-256 values, some explicitly described as **hashes of HTTP
request bodies, not files** (so they only match byte-for-byte captures). The restructured page exposes fewer
hashes in its text form. We are not republishing hash values we can no longer see in the current revision;
retrieve them from DeCYFIR or the advisory directly, and treat any request-body hash as a capture artefact, not
a file IOC.

## Tradecraft described

- **Node rotation and burn discipline:** filtered or rate-limited addresses are removed from the active set
  and not reused.
- **Low-and-slow pacing**, with separation between scanning and staging infrastructure.
- Closed **I2P channel**; operators discuss the target list, country split, and "infrastructure providers,
  telco, government and bank ranges".
- CYFIRMA says the 216-host set was captured with the final octet masked in its public report.

## Suggested hunt (use V4 as current, V1–V3 for retro-hunting)

```spl
(index=proxy OR index=firewall OR index=web)
| search (src_ip IN ("152.237.230.31","117.83.155.42","152.237.230.36","85.11.190.112","138.199.43.94",
   "23.234.113.169","118.186.18.243","2.59.133.151","141.98.255.246","156.225.28.97","178.249.214.6",
   "64.11.92.102","161.97.178.84","161.97.179.152","47.250.155.133","186.22.19.172","119.59.101.74",
   "185.177.72.45","32.236.50.30","32.236.55.80","223.178.86.187","112.245.227.143","95.179.220.151",
   "79.193.197.168"))
| search (url="*PHP_SESSION_UPLOAD_PROGRESS*" OR http_user_agent IN ("php2shell-scan/109618",
   "php2shell-test/2.0.0") OR status=200)
| stats count min(_time) max(_time) values(url) by src_ip, http_user_agent
```

For retro-hunting the V1–V3 lists, drop them into the same query. Prioritise any address that **scanned and
then succeeded** against a PHP endpoint; scanning alone is noise.

## Caveats

- Suspected infrastructure from a closed-channel source plus infrastructure correlation; **attribution and
  ownership unverified by us**. Some addresses are likely compromised third-party hosts or proxy egress.
- The advisory itself rotates indicators: V4 adds and may supersede earlier sets. Pull the DeCYFIR IOC set or
  re-check before operational blocking.
- Do not treat scanning as compromise.
