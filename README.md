# NOC Network & Firewall Operations Lab

A small company edge built on KVM and run the way a NOC runs it. It has an OPNsense firewall with three zones,
a least-privilege policy managed as code, changes that revert themselves unless they are confirmed, SNMPv3
and syslog monitoring in Zabbix, a runbook for every alert, and fault drills that measure time to detect.

It uses the same Zabbix server as the [NOC Monitoring & Incident Response Lab](https://github.com/phuochuyy/noc-monitoring-incident-lab),
which also monitors my Oracle RAC / Data Guard lab, so network alerts and database alerts reach one console.

## Topology

```
                 noc-wan 10.90.0.0/24 (libvirt NAT = "internet")
                   |                         |
                   | 10.90.0.2 (DHCP)        inet1 10.90.0.50  (outside machine: tests, port scan)
             +-----+------+
             |    fw1     |  OPNsense 26.7.8_2 (FreeBSD 15.1), 2 vCPU, 1 GB
             +--+------+--+
      10.90.10.1|      |10.90.20.1
  noc-lan (isolated)  noc-dmz (isolated)
     |          |          |
  host        lan1       dmz1 10.90.20.10  nginx, published as WAN:8080
  10.90.10.254 10.90.10.10
  (admin workstation + monitoring server: Zabbix, syslog receiver)
```

Servers are Alpine 3.24 cloud images (1 vCPU, 256 MB) with a NoCloud seed (`02-vms/create-alpine.sh`). The host
has no address on the DMZ, so it reaches the DMZ only through the firewall, the same as any LAN machine.

## Policy (least privilege, default deny)

| From → To | Allowed | Everything else |
|-----------|---------|-----------------|
| LAN → DMZ | web (80, 443), ping | blocked and logged |
| LAN → internet | all | |
| LAN → firewall SNMP | monitoring server only | blocked and logged |
| DMZ → LAN | nothing (a compromised server cannot reach users) | blocked and logged |
| DMZ → firewall | DNS, NTP | GUI/SSH blocked and logged |
| DMZ → internet | web (updates), ping | blocked |
| internet → DMZ | the published site only (port forward WAN:8080 → dmz1:80) | dropped |
| internet → firewall | nothing | dropped |

- **Bootstrap by code.** `03-firewall/build_config.py` turns the factory `config.xml` into the base config:
  hostname, a bcrypt root password from `lab.env`, SSH by key on LAN only, interfaces, DHCP, and the port
  forward. The result is restored through the backup page. Nothing is clicked by hand.
- **Policy by code.** `03-firewall/apply_policy.py` uses the OPNsense API and is safe to re-run. Rules are
  matched by description, and the two factory "allow LAN to any" rules are replaced by explicit rules.
- **Commit confirmed.** OPNsense 26.7 no longer has the filter savepoint/rollback API. Before each apply, the
  script snapshots `config.xml` and arms a revert job **on the firewall** (60 s). It then applies the change
  and logs in again from the admin workstation. Only when that works does it disarm the job. If a change cuts
  off the admin, nobody disarms it, and the firewall restores itself and logs `noc-change`.

## Results

| Test | Result | Evidence |
|------|--------|----------|
| Policy matrix: every path tested in its allowed and its blocked direction, from 4 vantage points | run 1: 16 PASS, 2 FAIL (both were faults in my tests, see below); run 2: **20 PASS, 0 FAIL** | [r1](results/policy-matrix-r1.txt), [r2](results/policy-matrix-r2.txt), [rules](results/raw/fw1-rules-r1.json), [pf ruleset](results/raw/fw1-pf-ruleset-r1.txt) |
| Patch before adding the SNMP plugin | 26.7 (FreeBSD 15.1-p1) → **26.7.8_2** (15.1-p6) | [before](results/raw/fw1-firmware-before.txt), [after](results/raw/fw1-firmware-after.txt) |
| Drill: nginx stopped on dmz1 | site-down alert **59.0 s**, resolved 58.1 s after restart | [net-drills-r1](results/net-drills-r1.log) |
| Drill: DMZ cable pulled (`domif-setlink down`) | SNMP link down **11.4 s**, web check 44.4 s; resolved 24.8 s / 57.8 s | [net-drills-r1](results/net-drills-r1.log) |
| Drill: SYN scan of 1,000 ports from the internet side | **1,000 of 1,000 filtered**; alert names the source `10.90.0.50 (1733)` after **42.5 s** | [net-drills-r3](results/net-drills-r3.log) |
| Drill: a change applied and never confirmed | the firewall reverted itself; "change reverted" alert 81.2 s / 90.2 s after the change (the job waits 60 s); "config changed" **missed in run 1**, **4.2 s** in run 2 | [r1](results/net-drills-r1.log), [r2](results/net-drills-r2.log) |

Detection times are measured from the moment of the fault to the Zabbix problem event (`05-drills/net_drills.py`).
They depend on the polling intervals: web scenarios every 1 min, log items every 30 s, SNMP at the template's
intervals.

## Monitoring

| What | How |
|------|-----|
| Firewall health, interfaces, services | SNMPv3 **authPriv** (v2c not enabled), template "OPNsense by SNMP" |
| Reachability | ICMP from the Zabbix server (fw1, lan1, dmz1) |
| Published site | 2 web scenarios: through the port forward (as a customer sees it) and directly from the LAN. Each checks status 200, an expected text, and the response time |
| Who changed what | firewall syslog (RFC 5424) to a receiver container. The audit line (`user … changed configuration … in /api/…`) becomes an event alert. The SHA-256 of `config.xml` is the state check |
| Attacks | blocked inbound WAN packets per minute plus the top source of the last 60 s (port scan); failed SSH logins |
| Unconfirmed changes | the `noc-change` log tag: "reverted" is a High alert that a person closes |

There are 9 runbooks in [04-runbooks](04-runbooks/README.md) (why the alert matters, how to check, how to
fix, when to escalate). Change alerts are closed by a person after review, not by recovery.

## What went wrong (and was fixed)

The full list is in [notes/worklog.md](notes/worklog.md).
- **The change alert missed a change entirely** (revert run 1). The config hash was polled every 2 min, and
  the change plus its revert 61 s later fell between two polls. I added an event-based alert from the audit
  log, which caught the change in 4.2 s in run 2.
- **False positive:** the template reported "DHCP server is not running", but OPNsense now serves DHCP with
  dnsmasq. I disabled the template check on this host and added an item for dnsmasq.
- **Wrong scan source:** the first port-scan alert named the host's mDNS multicast. It now uses the top
  blocked source and waits until that source is known.
- **Two invalid tests** in policy run 1: one used IPv6, and one "internet" test ran from the host through the
  LAN. I fixed them with `curl -4` and a real outside VM.
- **My mistakes:**
  - While probing for an endpoint, I called `apply`, so the policy went live without the safety net. Access
    was checked right away, and the lesson is to probe only with read endpoints.
  - I booted the servers before the firewall.
  - Adding `NET_RAW` to the Zabbix container cost about 70 s of blind monitoring (recorded in the
    monitoring lab's worklog).

## Limits

- Everything is virtual on one host: a "cable pull" is a link state change in libvirt, and the internet is
  a NAT bridge.
- The SNMPv3 user uses SHA-1/AES-128, because those are the plugin's options. The firewall's pf counters
  come from syslog and `pfctl` over SSH, because the net-snmp plugin has no pf MIB.
- The OPNsense image was checked with SHA-256 and a signed checksum file. The signing key came from the
  same server, so it should also be compared with the fingerprint on the website.
- Problems of a disabled template trigger stay in the API (no OK event is sent). They are hidden in the UI.
- One firewall, so there is no CARP/HA pair yet.

## Layout

```
01-network/    libvirt networks (WAN NAT, LAN and DMZ isolated)
02-vms/        fw1 and Alpine server creation
03-firewall/   base config builder, API client, policy as code with commit confirmed
04-monitoring/ SNMPv3, syslog receiver, Zabbix configuration as code, agent checks
04-runbooks/   NET-01..NET-09
05-drills/     policy matrix, fault drills
results/       test and drill output (raw/ = exported state)
notes/         worklog
```

Secrets (root password, SNMPv3 keys) are kept in `lab.env`, which is git-ignored (see `lab.env.example`).
