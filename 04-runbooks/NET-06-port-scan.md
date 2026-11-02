# NET-06-port-scan: Possible port scan from the internet (> 100 blocked inbound WAN packets per minute)

**Severity:** Average

## Why it matters
Scans precede attacks; the policy should drop them all - this alert checks that it does and tells who scans.

## Check
1. Source: item *last WAN block*; `grep vtnet1,match,block ~/.local/state/noc-syslog/fw1.noc.lab.log | tail`.
1. Anything passed from that source? `pfctl -ss | grep <ip>`.

## Fix
1. All blocked: record the source; repeated: add it to a block alias.
1. Something passed: treat as an incident (which rule, which server).

## Escalate
Security owner if anything was let through.

## Close
Shift log: problem, cause, action, time to restore. Repeats: problem record.
