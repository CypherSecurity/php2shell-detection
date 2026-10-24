# php2shell detection package

Defensive detection and response material for **CVE-2026-109618** and **CVE-2026-109619**
("php2shell") — two critical vulnerabilities in PHP itself, fixed in **PHP 8.5.12 / 8.4.27 /
8.3.36 / 8.2.35** (released 2026-10-21).

Maintained alongside a continuously updated public advisory:
**<https://f4n6.co.uk/php2shell/>**

## What is in here

| Path | Contents |
|---|---|
| `01-threat-intel/` | Full threat-intel dossier, eight-page technical brief, technical annex |
| `02-detections/` | Suricata, Zeek, YARA, Sigma and ModSecurity rules, plus deployment notes |
| `03-hardening/` | Configuration hardening and mitigation guidance |
| `04-hunting/` | Hunting queries for SIEM and log platforms |
| `05-validation/` | Load-validation evidence for the rulesets |
| `06-soc-triage/` | Alert triage, false-positive tuning, incident-response runbook |
| `PATCH-AVAILABILITY.md` | Fixed versions by distribution and ecosystem, including PAN-OS |
| `PAN-OS-EXPOSURE.md` | PAN-OS/Panorama exposure, exploitability and estate checks |
| `INCIDENT-STATUS.md` | Victim/compromise status and why absence of reporting is not safety |
| `CLARIFICATION-second-vulnerability-claim.md` | What the "second vulnerability" claim got wrong, with sources |
| `START-HERE.md` | Reading order |

## This repository contains no exploit code

It is detection and response material only: rules, queries, triage guidance and analysis. The only
scanner referenced is a *defensive* inventory check.

## Verification

Every release publishes the ZIP together with its `.sha256` sidecar. Verify before deploying:

```sh
sha256sum -c php2shell-detection-package-*.zip.sha256
```

## Detections are load-validated

Suricata 8.0.3 (16 rules, clean `-T`), Zeek 9.0.0, YARA 4.5.5 and an Apache mod_security2
`configtest` were all used to confirm the rules parse and load.

## Scope notes worth knowing

- PHP 7.4, 8.0 and 8.1 are affected too (source backports only; distributions backported builds).
- `display_errors = Off` is not a security control for this bug class.
- Patching an application does not help — the PHP runtime must be updated.
- A package upgrade without a PHP worker restart leaves the host exploitable.

## Licence / use

Provided for defensive use. Attribution appreciated. No warranty.
