# Worklog

Problems met, causes, fixes and lessons (including my own mistakes).

## Build: network, firewall, servers (2026-11-02)

| Problem | Cause | Fix / lesson |
|---------|-------|--------------|
| OPNsense image authenticity | downloaded over the internet | SHA-256 of the image matches the published checksum file; the checksum file's signature verifies with `OPNsense-26.7.pub` (fetched from the same server - compare its fingerprint with the website for a stronger check) |
| A fresh OPNsense has a factory LAN address and password | design | the LAN bridge also carries 192.168.1.254 for bootstrap; the factory config is downloaded, rebuilt by `build_config.py` (bcrypt root password from `lab.env`, SSH key-only on LAN) and restored through the backup page |
| API read failed on `core/firmware/info` (IncompleteRead) | very large chunked response | not needed; only small API calls are used |
| **My mistake:** while looking for the savepoint endpoint, my probe POSTed `firewall/filter/apply` - the policy went live without the safety net | a probe that is not read-only | checked access right away (anti-lockout kept the LAN admin path); lesson: probe with GET / search endpoints only |
| `firewall/filter/savepoint` 404 in 26.7 | the filter savepoint/rollback API of older releases is gone | own "commit confirmed": snapshot `config.xml` and arm a revert job **on the firewall** (60 s), apply, verify from the admin workstation, then disarm. Confirmed 4.7 s after arming; log tag `noc-change` |
| `net-define` refused to redefine `noc-lan` | the XML has no UUID, so libvirt sees a new network with an existing name | `net-undefine` then `net-define` (VMs on that network stopped first and started again) |
| **My mistake:** lan1/dmz1 installed no packages on first boot | I started them while fw1 was shut down (network change) - no route out | boot order: firewall first. Also needed the next fix |
| Packages still failed after a clean re-run of cloud-init | Alpine's cloud-init does not write `/etc/resolv.conf` from the network-config nameservers | `write_files` of `resolv.conf` (runs before the package module); fixed in place on lan1/dmz1, inet1 built with the fix worked first time |
| SSH "host identification has changed" for lan1/dmz1 | `cloud-init clean` regenerates host keys (expected, caused by me) | removed the two lab entries from `known_hosts` |
| Policy matrix run r1: **2 FAIL** | (1) busybox `wget` picked an IPv6 address (the lab has none); (2) my "internet -> DMZ" test ran from the host, which reaches the DMZ through the LAN (nginx log: source 10.90.10.254) - an invalid test, not a hole | `curl -4`; a real internet-side VM (`inet1` on the WAN bridge, with a route to the DMZ range). Run r2: **20 PASS, 0 FAIL** |

## Monitoring and drills (2026-11-02 23:2x - 2026-11-03 00:1x)

| Problem | Cause | Fix / lesson |
|---------|-------|--------------|
| Plugin install refused: "update to opnsense-26.7.8_2 is required" | firmware older than the plugin repository | firmware update first (437 s, then a reboot; ping lost for at least 15.0 s - measured from after the reboot had started, so a lower bound): 26.7 -> 26.7.8_2, FreeBSD 15.1-p1 -> p6 |
| Template "OPNsense by SNMP": pf items "No Such Object" | the template is written for bsnmpd's pf MIB; the os-net-snmp plugin (net-snmp) has none | interface, process and service items work; pf numbers taken from syslog and `pfctl -si` over SSH instead |
| Third false positive: "OPNsense: DHCP server is not running" | the template looks for process `dhcpd`; OPNsense 25.x+ serves DHCP with dnsmasq | template item + trigger disabled on fw1, own item on the same SNMP process table for `dnsmasq` (NET-09). The disabled trigger's problem still shows in the API (no OK event for a disabled trigger); hidden in the UI |
| HTTP agent items returned the page body, not a time | wrong item type for the purpose (mine) | web scenarios: status 200 + expected text + response time per step |
| Port-scan alert named the wrong source (`10.90.0.1 -> 224.0.0.251:5353`) | "last blocked line" was an mDNS multicast of the host, not the scanner | top blocked source of the last 60 s (multicast/broadcast excluded); r2 then named "-" (top-source poll not run yet) -> the trigger waits for a known source: r3 names `10.90.0.50 (1733)`, detection 42.5 s instead of 22.7 s |
| **Config-change alert missed a change entirely (drill revert r1)** | the SHA-256 of config.xml is polled every 2 min; the change and its automatic revert (61 s later) fell between two polls: same hash before and after | event-based alert from the syslog audit line (`user root@10.90.10.254 changed configuration ... in /api/...`: who, from where, which API): r2 detected in 4.2 s; the hash stays as the state check |
| IPMI client of pyghmi fails against virtualbmc (`pack expected 32 items, got 20`) | cipher-suite / hash-length mismatch between the two libraries | use `ipmitool -I lanplus` (to install) |
