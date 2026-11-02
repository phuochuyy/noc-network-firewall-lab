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
