# NET-08-ssh-failed: Failed SSH logins on the firewall

**Severity:** Warning

## Why it matters
SSH listens on LAN only and accepts keys only: failures mean a misconfigured client or someone on the LAN trying.

## Check
1. `grep sshd ~/.local/state/noc-syslog/fw1.noc.lab.log | tail` (source address, user).

## Fix
1. Known client: fix its key. Unknown source on the LAN: find the device (DHCP leases) and escalate.

## Escalate
Security owner for unknown sources.

## Close
Shift log: problem, cause, action, time to restore. Repeats: problem record.
