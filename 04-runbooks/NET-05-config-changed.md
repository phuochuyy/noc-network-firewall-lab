# NET-05-config-changed: Firewall configuration changed (SHA-256 of config.xml)

**Severity:** Information, closed by hand

## Why it matters
Every change must match a change record. A change nobody can explain is a security incident.

## Check
1. Who/when: `grep -h 'noc-change\|config' ~/.local/state/noc-syslog/fw1.noc.lab.log | tail`; OPNsense: System > Configuration > History (diff).

## Fix
1. Matches a change record: acknowledge with its number and close.
1. No record: revert from the history and escalate.

## Escalate
Security owner for an unexplained change.

## Close
Shift log: problem, cause, action, time to restore. Repeats: problem record.
