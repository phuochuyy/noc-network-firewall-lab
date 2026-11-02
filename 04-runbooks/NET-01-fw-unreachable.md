# NET-01-fw-unreachable: Firewall unreachable by ICMP (template 'ICMP Ping')

**Severity:** High

## Why it matters
Everything behind fw1 (LAN users' internet, the published web site) depends on it.

## Check
1. `virsh -c qemu:///system domstate fw1`; console: `virsh -c qemu:///system console fw1`.
1. From the host: `ping 10.90.10.1`, `ping 10.90.0.2`.

## Fix
1. VM down: start it (`virsh start fw1`), then the servers behind it (boot order: firewall first).
1. VM up but no answer: console, `ifconfig`, `pfctl -si`; last change? (NET-05).

## Escalate
Network owner immediately.

## Close
Shift log: problem, cause, action, time to restore. Repeats: problem record.
