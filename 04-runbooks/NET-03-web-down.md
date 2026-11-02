# NET-03-web-down: Published web site failing (web scenario from the monitoring server)

**Severity:** High

## Why it matters
The customer-facing check: WAN 10.90.0.2:8080 -> port forward -> dmz1 nginx. 'Direct' scenario tells whether the server or the path is broken.

## Check
1. Direct scenario OK and published failing: NAT / WAN rule on fw1.
1. Both failing: dmz1 (`ssh -J root@10.90.10.1 alpine@10.90.20.10 rc-service nginx status`) or the DMZ link (NET-02).

## Fix
1. Restart the service (`doas rc-service nginx restart`); last resort: power-cycle dmz1 through its BMC (`ipmitool ... power reset`).

## Escalate
Application owner if nginx fails to start.

## Close
Shift log: problem, cause, action, time to restore. Repeats: problem record.
