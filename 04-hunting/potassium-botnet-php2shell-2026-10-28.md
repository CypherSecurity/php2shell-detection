# Potassium (Mirai fork) delivered via php2shell — IOCs and hunting

**Compiled:** 2026-10-28. **Provenance:** aggregated from a public exploitation tracker
(`ikow/php2shell-poc`, docs/EXPLOITATION.md, MIT) which cites **Nokia Deepfield, Sophos, Arctic Wolf, Wiz,
Wordfence and SOCRadar** for the individual indicators. **We have not independently verified these IOCs**.
Treat them as lead generation, not as confirmed blocking intelligence. Defanged for safety.

## Why this matters

The picture widened from targeted exploitation to **commodity botnet delivery**. A Mirai-derived DDoS
botnet tracked as **Potassium** was delivered through php2shell starting 2026-10-22, per Nokia Deepfield and
Sophos. That changes the risk for PHP web estates: the payload is not data theft or espionage, it is
recruitment into a DDoS botnet, and it happens opportunistically.

## Payload hashes (SHA-256)

| Hash | Architecture | Source |
|---|---|---|
| `e2529d4afa39ae4db2eb05d5176317c906289abf09660c75bdeec43e54c55aa3` | Potassium x86_64 | Arctic Wolf |
| `0c5486f06620e26e316f4b33f318b0d646d5e1133789331aa2fed012360d1486` | Potassium ARM | Arctic Wolf |

## Network indicators (defanged)

### Loader and payload delivery
| Type | Value | Context |
|---|---|---|
| IP | `92.118.112[.]100` | Potassium loader host |
| URL | `hxxp://92.118.112[.]100/nfs-setup` | Potassium x86 payload |
| URL | `hxxp://92.118.112[.]100/mountpoint` | Potassium ARM payload |
| IP | `134.199.154[.]64` | Potassium C2 |
| Domain | `thunder[.]godofthunder[.]st` | Potassium C2 for this campaign |
| Domain | `hackattackkaboom[.]botlesscucks[.]st` | Potassium update host |
| URL | `hxxp://45.115.26[.]26:8000/cCmono` | Secondary payload |

### Other campaign infrastructure
| Type | Value | Context |
|---|---|---|
| IP | `45.153.34[.]245` | `iambig` campaign C2 |
| IP | `45.156.87[.]243` | `botlesscucks` campaign C2 |
| IP | `31.56.197[.]72` | C2 / payload server |
| IP | `206.188.197[.]105:9999` | Attacker tooling server (`aslr_exploit.py`) |
| IP | `45.198.224[.]169` | Attack source |
| IP | `85.11.167[.]243` | Attack source |
| IP | `217.60.242[.]76` | Attack source |

### Scanning sources (Wordfence)
`87.121.84[.]174`, `181.215.186[.]252`, `185.196.220[.]132`, `185.161.210[.]29`, `152.233.51[.]69`,
`45.134.225[.]16`, `107.189.14[.]87`, `193.47.62[.]24`, `103.147.220[.]17`

The two source clusters from the 0x4D31 honeypot dataset (`15.204.59[.]70`, `162.35.99[.]94`) also appear in
the tracker, attributed there to Wiz. That is cross-source agreement on the same two clusters.

## Potassium bot behaviour (Nokia Deepfield)

| Signal | Detail |
|---|---|
| Wire encoding | all C2 traffic XOR `0xED` |
| Registration header | 19-byte fixed header `0a0b0c0d0e0f00030201020304050504030201` |
| Port pools | Pool A: 876, 1207, 6428, 7574, 19876, 26608, 27603, 27776, 29502, 57536, 60764 |
| | Pool B: 7193, 15987, 23789, 27651, 32876, 38429, 42061, 46852, 49376, 54123, 61543 |
| Process names | `dvrLocker`, `dvrInside` |
| Banner | `it was never about the taste` |
| Local listener | TCP 1234 on egress IP or `127.0.0.1` |
| DNS trick | query `8.8.8.8:53`, then connect to halves-swapped IP |
| C2 port | TCP 50792 |

## Request signatures seen in the wild

| Indicator | Value |
|---|---|
| User-Agent | `php2shell-scan/109618` |
| User-Agent | `php2shell-test/2.0.0` |
| User-Agent | `Mozilla/5.0 (php2shell-test/2.0.0)` |
| Multipart boundary | `----p2shell` |
| Multipart field | `PHP_SESSION_UPLOAD_PROGRESS` |
| Default PoC command | `uname -a; id; echo JACKALPOC` |

Note the new boundary: `----p2shell`. We had `CCCCCCCCCC` (Joas kit), `B7kQpoc618`, and `----wp2shell`
look-alike; this is another kit family to add to the boundary list. Absent or unusual `User-Agent` remains a
useful companion signal.

## Hunting queries

### Splunk
```spl
(index=web OR index=proxy)
| search (url="*/nfs-setup" OR url="*/mountpoint" OR url="*/cCmono")
   OR (query="thunder.godofthunder.st" OR query="hackattackkaboom.botlesscucks.st")
   OR (http_user_agent IN ("php2shell-scan/109618","php2shell-test/2.0.0","Mozilla/5.0 (php2shell-test/2.0.0)"))
| stats count min(_time) max(_time) by src_ip, url, http_user_agent
```

### Elastic
```
http.request.method: POST and http.request.body.content:*PHP_SESSION_UPLOAD_PROGRESS*
or dns.question.name:(thunder.godofthunder.st or hackattackkaboom.botlesscucks.st)
or url.full:(*/nfs-setup or */mountpoint or */cCmono)
or user_agent.original:(php2shell-scan* or php2shell-test*)
```

### Defender / eBPF
- Process names `dvrLocker`, `dvrInside`
- Listener on TCP 1234, outbound to C2 port 50792
- `wget`/`curl` child of a web server process fetching `/nfs-setup` or `/mountpoint`

## Caveats

- Single aggregated source for the IOC set; individual indicators are attributed to named firms but we have
  not verified each one. Do not block IPs without corroboration, and expect the loader infrastructure to
  rotate.
- Botnet indicators age fast. Re-check the tracker and Nokia Deepfield before operational use.
- The upstream tracker's own warning is worth repeating: many GitHub "php2shell" repos
  contain non-functional code or malware. Do not run unknown tooling.
