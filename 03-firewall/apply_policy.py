"""Firewall policy as code (OPNsense API), applied the way a change should be ("commit confirmed"):

  1. snapshot /conf/config.xml on the firewall and arm a revert job there (60 s, dead man's switch)
  2. save and apply the rules through the API  3. verify from the admin workstation (API login again)
  4. only then disarm the revert. If the change cuts the admin off, nobody disarms it and the box reverts itself.
  (OPNsense 26.7 no longer exposes the filter savepoint/rollback API that older releases had.)

Rules managed here carry the prefix "[noc] " in the description; others are left alone except the two factory
"Default allow LAN" rules, which are disabled (replaced by explicit rules). Re-runnable: rules are matched by
description and updated in place.

Zones: LAN 10.90.10.0/24 (users, admin), DMZ 10.90.20.0/24 (published servers), WAN = internet.
Principle: DMZ may never open a connection into LAN; LAN reaches DMZ only on web ports; everything not
allowed is dropped and logged (default deny).

usage: ~/work/tools/venvs/noc/bin/python apply_policy.py [--dry-run]
"""
import subprocess
import sys
import time

from opn import OPN

P = "[noc] "
ALIASES = [
    {"name": "web_ports", "type": "port", "content": "80\n443", "description": P + "HTTP, HTTPS"},
]
# (sequence, interface, action, protocol, source, destination, port, log, description)
RULES = [
    (101, "lan", "pass", "UDP", "10.90.10.254", "(self)", "161", "0", "monitoring server SNMP to the firewall"),
    (102, "lan", "block", "UDP", "lan", "(self)", "161", "1", "LAN users: no SNMP to the firewall"),
    (110, "lan", "pass", "TCP", "lan", "opt1", "web_ports", "0", "LAN to DMZ web (80, 443)"),
    (120, "lan", "pass", "ICMP", "lan", "any", "", "0", "LAN ping (troubleshooting)"),
    (130, "lan", "block", "any", "lan", "opt1", "", "1", "LAN to DMZ: everything else blocked"),
    (140, "lan", "pass", "any", "lan", "any", "", "0", "LAN to internet"),
    (210, "opt1", "pass", "TCP/UDP", "opt1", "(self)", "53", "0", "DMZ DNS to the firewall"),
    (220, "opt1", "pass", "UDP", "opt1", "(self)", "123", "0", "DMZ NTP to the firewall"),
    (230, "opt1", "block", "any", "opt1", "lan", "", "1", "DMZ to LAN blocked (a compromised server cannot reach users)"),
    (240, "opt1", "block", "any", "opt1", "(self)", "", "1", "DMZ to the firewall itself blocked (GUI, SSH)"),
    (250, "opt1", "pass", "TCP", "opt1", "any", "web_ports", "0", "DMZ updates out (80, 443)"),
    (260, "opt1", "pass", "ICMP", "opt1", "any", "", "0", "DMZ ping out"),
]
FACTORY_ALLOW = ("Default allow LAN to any rule", "Default allow LAN IPv6 to any rule")


def rule_body(seq, ifc, action, proto, src, dst, port, log, descr):
    return {"enabled": "1", "sequence": str(seq), "action": action, "quick": "1", "interface": ifc,
            "direction": "in", "ipprotocol": "inet", "protocol": proto, "source_net": src,
            "destination_net": dst, "destination_port": port, "log": log, "description": P + descr}


def ensure_aliases(o, dry):
    have = {a["name"]: a["uuid"] for a in o.api("firewall/alias/search_item", {"rowCount": -1})["rows"]}
    for a in ALIASES:
        body = {"alias": {"enabled": "1", **a}}
        if dry:
            print(("update" if a["name"] in have else "add"), "alias", a["name"])
        elif a["name"] in have:
            o.api(f"firewall/alias/set_item/{have[a['name']]}", body)
        else:
            r = o.api("firewall/alias/add_item", body)
            assert r.get("result") == "saved", r
    if not dry:
        o.api("firewall/alias/reconfigure", {})


FW = "root@10.90.10.1"
ARM = ("cp /conf/config.xml /tmp/noc-rollback.xml && touch /tmp/noc-rollback.armed && "
       "(sleep {t}; if [ -f /tmp/noc-rollback.armed ]; then cp /tmp/noc-rollback.xml /conf/config.xml && "
       "configctl filter reload && logger -t noc-change 'policy change reverted (not confirmed)'; fi) "
       ">/dev/null 2>&1 &")
DISARM = "rm -f /tmp/noc-rollback.armed && logger -t noc-change 'policy change confirmed'"


def fw(cmd):
    return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", FW, f"sh -c \"{cmd}\""],
                          check=True, capture_output=True, text=True).stdout


def main(dry=False, timeout=60):
    o = OPN().login()
    if not dry:
        fw(ARM.format(t=timeout))
        armed_at = time.time()
        print(f"revert armed on the firewall ({timeout} s)")
    ensure_aliases(o, dry)
    rows = o.api("firewall/filter/search_rule", {"rowCount": -1})["rows"]
    by_descr = {r["description"]: r for r in rows}
    want = {P + r[-1] for r in RULES}
    for r in RULES:
        body = {"rule": rule_body(*r)}
        cur = by_descr.get(P + r[-1])
        if dry:
            print("update" if cur else "add", P + r[-1])
            continue
        res = o.api(f"firewall/filter/set_rule/{cur['uuid']}", body) if cur else o.api("firewall/filter/add_rule", body)
        assert res.get("result") == "saved", (r[-1], res)
    for d, row in by_descr.items():
        if d.startswith(P) and d not in want:
            print("delete", d) if dry else o.api(f"firewall/filter/del_rule/{row['uuid']}", {})
        if d in FACTORY_ALLOW and row.get("enabled") == "1":
            print("disable", d) if dry else o.api(f"firewall/filter/toggle_rule/{row['uuid']}/0", {})
    if dry:
        return
    print("apply:", o.api("firewall/filter/apply", {}))
    time.sleep(3)
    try:  # the admin workstation must still reach the firewall over the new rules
        OPN().login().api("firewall/filter/search_rule", {"rowCount": 1})
        fw(DISARM)
    except Exception as e:  # noqa: BLE001
        sys.exit(f"verification failed ({e}): not confirmed, the firewall reverts by itself")
    print(f"verified and confirmed {time.time() - armed_at:.1f} s after arming")


if __name__ == "__main__":
    main("--dry-run" in sys.argv)
