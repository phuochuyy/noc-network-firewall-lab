# NET-02-link-down: Firewall interface link down (template trigger, SNMP ifOperStatus)

**Severity:** Average

## Why it matters
A link down on DMZ cuts the published site; on LAN cuts the users; on WAN cuts the internet.

## Check
1. Which interface: vtnet0 LAN, vtnet1 WAN, vtnet2 DMZ.
1. `virsh -c qemu:///system domif-getlink fw1 <vnetX>` (the 'cable').

## Fix
1. Restore the link (`domif-setlink ... up` in the lab; in a data centre: cable, switch port, SFP).
1. Confirm with NET-03 that the service is back.

## Escalate
Network owner; data-centre remote hands for a physical link.

## Close
Shift log: problem, cause, action, time to restore. Repeats: problem record.
