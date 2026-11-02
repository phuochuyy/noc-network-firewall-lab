# NET-09-dhcp-down: DHCP server (dnsmasq) not running on the firewall

**Severity:** Average

## Why it matters
New devices on the LAN get no address; existing leases keep working until they expire. (The template's own check looks for 'dhcpd' and is disabled here: OPNsense 25.x+ uses dnsmasq.)

## Check
1. `ssh root@10.90.10.1 'configctl dnsmasq status'`

## Fix
1. `configctl dnsmasq restart`; check the dnsmasq log on fw1.

## Escalate
-

## Close
Shift log: problem, cause, action, time to restore. Repeats: problem record.
