# NET-04-web-slow: Published web site slower than 1 s for 5 min

**Severity:** Warning

## Why it matters
Users see it before it fails.

## Check
1. Response time of both scenarios; pf states (item); interface errors/discards (SNMP).

## Fix
1. Find the slow hop: direct fast + published slow = firewall; both slow = server.

## Escalate
-

## Close
Shift log: problem, cause, action, time to restore. Repeats: problem record.
