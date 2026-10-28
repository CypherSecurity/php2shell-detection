# Hunting guide: appliance rooted via PHP2Shell + Fragnesia (Dream report, 25-27 Oct 2026)

**Source:** Dream Group, *"Chained PHP2Shell Exploit Roots 25 Servers, including US Government Servers"*,
27 Oct 2026 (artifacts discovered 25 Oct). THN summary 28 Oct. No IOCs published, vendor and versions
withheld. Single-source, vendor-reported, not independently verified.

**Why it matters:** this is the first vendor-reported real-world compromise chain using these CVEs. It did
not use the public PoC. It rooted appliances through an exposed management interface, then chained a Linux
kernel LPE for root.

## The chain, in order

1. **Discovery:** FOFA search for ~19,000 internet-facing firewalls (undisclosed vendor) with exposed
   management interfaces.
2. **Fingerprint:** custom scanner, ~5,000 alive with OS version, filtered to US / JP / TW / KR and PHP
   **8.0.30** branches, yielding 240 targets.
3. **Exploit:** custom PHP2Shell build against the **`session.upload_progress`** mechanism on the
   appliance's **appweb management server**. One HTTP request per chain. Stages: A1 memory exhaustion
   (~383 MB), B1 out-of-bounds leak in a `Set-Cookie`, A2 stale reference setup (~500 MB), B2 forged
   HashTable with `pDestructor` = `zif_system`. Code execution as **`nobody`**.
4. **Root:** **Fragnesia, CVE-2026-46300** (Linux kernel LPE, XFRM ESP-in-TCP). Page-cache write replaces
   `/etc/pam.d/su` with a 774-byte file pointing at `pam_permit.so`.
5. **Persistence and pivot:** a **103-byte PHP root web shell** in a web-accessible directory; an
   **8-port reverse SSH tunnel** (LDAP, LDAPS, RDP, internal management, VPN, SOCKS5) persisted via a
   **systemd service** and an **`rc.local` hook**; AD enumeration, LDAP service-account password decrypted
   from device config, password spray with **`lockoutThreshold=0`**, attempted backdoor user and machine
   accounts, SAML/Keycloak key access attempts.

25 servers rooted in total (24 firewalls plus one internal management server), including three US
government-affiliated systems. 22 further firewalls were left parked with web shells.

## Detection: highest-value checks

### On the appliance itself
- New or modified **`.php` files in web-accessible directories** on the management server. Look for very
  small files (the reported web shell is 103 bytes) that echo command output or accept a command parameter.
- **Reverse SSH** connections from the appliance outbound to the internet. Process lineage and config:
  `ssh -R …`, autossh, or connections to non-management destinations. Check for a **systemd unit** or
  **`rc.local`** entry starting that tunnel.
- **`/etc/pam.d/su`** content or hash change, especially any reference to **`pam_permit.so`**. Also check
  other PAM files and kernel page-cache integrity (file hash vs package hash).
- **Kernel version** cannot confirm or rule out Fragnesia; patch state can. Compare against vendor kernel
  advisories for CVE-2026-46300.

### In the management logs
- Multipart POSTs to the management interface carrying **`PHP_SESSION_UPLOAD_PROGRESS`** and very large
  fields, with unusual or absent `User-Agent`, especially to the appliance's management hostname (not the
  data plane).
- Spikes of **~400 MB to 1 GB** of request bodies from one source against the management surface.
- A **`Set-Cookie`** response containing an anomalously large `PHPSESSID` (hundreds of KB) or pointer-like
  binary content.

### In identity logs
- **LDAP enumeration bursts** originating from the appliance management server's IP (the device already
  holds an LDAP service account, so source IP alone is not suspicious, but volume and scope are).
- **Password spray** against every domain user from that source, especially with no lockout observed.
- Attempts to **create user or machine accounts** in multiple OUs.
- **Keycloak/SAML IdP** configuration or signing-key access from the management server.

### On the network
- The appliance initiating **LDAP/LDAPS/RDP/VPN** connections it never made before.
- **SOCKS5** or unusual long-lived outbound tunnels from the appliance.
- Lateral movement from appliance management VLAN into domain controllers.

## What to do if any of this matches

1. Treat the management plane as compromised: isolate the appliance, do not just patch it.
2. Acquire the appliance filesystem before reimaging (web shells, tunnel units, PAM changes).
3. Rotate **everything** the device holds: LDAP service account, HA keys, TLS and device-auth keys, SAML
   signing material.
4. Hunt AD for the spray and backdoor accounts; check `lockoutThreshold`, `MachineAccountQuota`, and
   authentication from the management server.
5. Patch both layers: the PHP runtime fix (or vendor firmware) and the kernel LPE.

## Limits

Vendor and versions withheld, no IOCs, no hashes, no IPs. These checks are designed from described
behaviour, not from observed artefacts. They may produce false positives on legitimate appliance
management and automation, so baseline first.
