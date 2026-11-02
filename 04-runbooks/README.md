# Runbooks

One per trigger (the trigger URL opens it): why it matters, check, fix, escalate.

| ID | Trigger | Severity |
|----|---------|----------|
| [NET-01-fw-unreachable](NET-01-fw-unreachable.md) | Firewall unreachable by ICMP (template 'ICMP Ping') | High |
| [NET-02-link-down](NET-02-link-down.md) | Firewall interface link down (template trigger, SNMP ifOperStatus) | Average |
| [NET-03-web-down](NET-03-web-down.md) | Published web site failing (web scenario from the monitoring server) | High |
| [NET-04-web-slow](NET-04-web-slow.md) | Published web site slower than 1 s for 5 min | Warning |
| [NET-05-config-changed](NET-05-config-changed.md) | Firewall configuration changed (SHA-256 of config.xml) | Information, closed by hand |
| [NET-06-port-scan](NET-06-port-scan.md) | Possible port scan from the internet (> 100 blocked inbound WAN packets per minute) | Average |
| [NET-07-change-reverted](NET-07-change-reverted.md) | A firewall policy change was not confirmed and reverted itself | High, closed by hand |
| [NET-08-ssh-failed](NET-08-ssh-failed.md) | Failed SSH logins on the firewall | Warning |
| [NET-09-dhcp-down](NET-09-dhcp-down.md) | DHCP server (dnsmasq) not running on the firewall | Average |
