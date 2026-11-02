"""Put the network lab into the Zabbix of noc-monitoring-incident-lab (configuration as code, re-runnable).

  fw1    SNMPv3 authPriv (SHA/AES, the plugin's algorithms) + "OPNsense by SNMP" + "ICMP Ping";
         active checks by the KVM host's agent (host name "fw1" in its Hostname list): config hash, syslog
  dmz1   "ICMP Ping" + web scenarios: direct (LAN -> DMZ :80, allowed) and published (WAN 10.90.0.2:8080)
  lan1   "ICMP Ping"
SNMP passphrases are host-level *secret* macros, from ../lab.env. Every trigger added here has a runbook.

usage: python3 zabbix_net.py
"""
import pathlib
import sys

ZBX = pathlib.Path.home() / "work/noc-monitoring-incident-lab/01-stack"
sys.path.insert(0, str(ZBX))
from zbx import Zabbix  # noqa: E402

ENV = pathlib.Path(__file__).resolve().parent.parent / "lab.env"
RUNBOOK = "file:///home/huy/work/noc-network-firewall-lab/04-runbooks/"


def env():
    return dict(l.split("=", 1) for l in ENV.read_text().splitlines() if "=" in l and not l.startswith("#"))


def gid(z, name):
    g = z.call("hostgroup.get", {"filter": {"name": name}})
    return g[0]["groupid"] if g else z.call("hostgroup.create", {"name": name})["groupids"][0]


def tids(z, names):
    t = z.call("template.get", {"filter": {"host": names}, "output": ["templateid"]})
    assert len(t) == len(names), names
    return [{"templateid": x["templateid"]} for x in t]


def upsert_host(z, host, group, templates, interface, macros):
    body = {"groups": [{"groupid": gid(z, group)}], "templates": tids(z, templates), "macros": macros}
    old = z.call("host.get", {"filter": {"host": host}, "output": ["hostid"], "selectInterfaces": ["interfaceid"]})
    if old:
        hid = old[0]["hostid"]
        z.call("host.update", {"hostid": hid, **body})
        for i in old[0]["interfaces"]:
            z.call("hostinterface.update", {"interfaceid": i["interfaceid"], **interface})
    else:
        hid = z.call("host.create", {"host": host, "interfaces": [{"main": 1, **interface}], **body})["hostids"][0]
    return hid


def upsert_item(z, hid, key, **kw):
    old = z.call("item.get", {"hostids": hid, "filter": {"key_": key}, "output": ["itemid"]})
    if old:
        z.call("item.update", {"itemid": old[0]["itemid"], **kw})
        return old[0]["itemid"]
    return z.call("item.create", {"hostid": hid, "key_": key, **kw})["itemids"][0]


def upsert_trigger(z, hid, runbook, **kw):
    url = RUNBOOK + runbook
    old = [t for t in z.call("trigger.get", {"hostids": hid, "output": ["triggerid", "url"], "inherited": False})
           if t["url"] == url]
    body = {"url": url, "url_name": "Runbook " + runbook.removesuffix(".md"), **kw}
    if old:
        z.call("trigger.update", {"triggerid": old[0]["triggerid"], **body})
    else:
        z.call("trigger.create", body)


def main():
    e = env()
    z = Zabbix.from_env()
    snmp = {"type": 2, "useip": 1, "ip": "10.90.10.1", "dns": "", "port": "161",
            "details": {"version": 3, "bulk": 1, "securityname": "{$SNMPV3_USER}", "securitylevel": 2,
                        "authprotocol": 1, "authpassphrase": "{$SNMPV3_AUTH}",
                        "privprotocol": 1, "privpassphrase": "{$SNMPV3_PRIV}", "contextname": ""}}
    fw = upsert_host(z, "fw1", "Lab/Network", ["OPNsense by SNMP", "ICMP Ping"], snmp, [
        {"macro": "{$SNMPV3_USER}", "value": e["SNMP_USER"]},
        {"macro": "{$SNMPV3_AUTH}", "value": e["SNMP_AUTH"], "type": 1},
        {"macro": "{$SNMPV3_PRIV}", "value": e["SNMP_PRIV"], "type": 1}])
    agent_if = lambda ip: {"type": 1, "useip": 1, "ip": ip, "dns": "", "port": "10050"}  # noqa: E731 (ping only)
    dmz = upsert_host(z, "dmz1", "Lab/Network", ["ICMP Ping"], agent_if("10.90.20.10"), [])
    upsert_host(z, "lan1", "Lab/Network", ["ICMP Ping"], agent_if("10.90.10.10"), [])

    # web scenarios (run by the Zabbix server): status code 200 + expected text, response time per step
    old = {h["name"]: h["httptestid"] for h in z.call("httptest.get", {"hostids": dmz, "output": ["name"]})}
    for name, url in [("Published site (WAN 10.90.0.2:8080)", "http://10.90.0.2:8080/"),
                      ("Direct (LAN -> DMZ 10.90.20.10:80)", "http://10.90.20.10/")]:
        body = {"name": name, "delay": "1m", "retries": 1,
                "steps": [{"name": "home", "url": url, "status_codes": "200", "required": "dmz1 web",
                           "timeout": "5s", "no": 1}]}
        if name in old:
            z.call("httptest.update", {"httptestid": old[name], **{k: v for k, v in body.items() if k != "name"}})
        else:
            z.call("httptest.create", {"hostid": dmz, **body})
    # HTTP agent items of the first version (returned the page body, not a time): removed
    stale = z.call("item.get", {"hostids": dmz, "search": {"key_": "web.dmz1."}, "output": ["itemid"]})
    if stale:
        z.call("item.delete", [i["itemid"] for i in stale])
    pub = "Published site (WAN 10.90.0.2:8080)"
    upsert_trigger(z, dmz, "NET-03-web-down.md", priority=4,
                   description="dmz1: published web site failing (step {ITEM.LASTVALUE})",
                   expression=f"last(/dmz1/web.test.fail[{pub}])<>0")
    upsert_trigger(z, dmz, "NET-04-web-slow.md", priority=2,
                   description="dmz1: published web site slow (> 1 s for 5 min)",
                   expression=f"min(/dmz1/web.test.time[{pub},home,resp],5m)>1")

    # --- fw1: active checks by the host agent (SSH + the syslog file written by the receiver container)
    log = "/home/huy/.local/state/noc-syslog/fw1.noc.lab.log"
    # filterlog CSV: rule,sub,anchor,label,IF,reason,ACTION,DIR,4,tos,ecn,ttl,id,off,flags,proto#,PROTO,len,SRC,DST,sport,DPORT
    wan_block = ("filterlog\\[[0-9]+\\] [0-9]*,[^,]*,[^,]*,[^,]*,vtnet1,match,block,in,4,[^,]*,[^,]*,[^,]*,"
                 "[^,]*,[^,]*,[^,]*,[^,]*,(tcp|udp),[^,]*,([0-9.]+),([0-9.]+),[0-9]*,([0-9]+)")
    z.call("host.update", {"hostid": fw, "macros": [
        {"macro": "{$SNMPV3_USER}", "value": e["SNMP_USER"]},
        {"macro": "{$SNMPV3_AUTH}", "value": e["SNMP_AUTH"], "type": 1},
        {"macro": "{$SNMPV3_PRIV}", "value": e["SNMP_PRIV"], "type": 1},
        {"macro": "{$WAN.BLOCK.SCAN}", "value": "100", "description": "blocked inbound WAN packets per minute"}]})
    upsert_item(z, fw, "noc.fw.confighash", name="Firewall: configuration SHA-256", type=7, value_type=1,
                delay="2m", history="90d", trends="0", description="sha256 of /conf/config.xml over SSH")
    upsert_item(z, fw, "noc.fw.pf.states", name="Firewall: pf state entries", type=7, value_type=3, delay="1m")
    upsert_item(z, fw, f'log.count[{log},"{wan_block}",,,skip]', name="Firewall: WAN inbound blocked per minute",
                type=7, value_type=3, delay="1m")
    upsert_item(z, fw, f'log[{log},"{wan_block}",,,skip,"\\2 -> \\3:\\4/\\1"]',
                name="Firewall: last WAN block (source -> destination:port/proto)", type=7, value_type=2,
                delay="1m", history="7d")
    upsert_item(z, fw, "noc.fw.wan.topsrc", name="Firewall: top blocked WAN source, last 60 s", type=7,
                value_type=1, delay="1m", history="7d", trends="0")
    audit = f'log[{log},"audit.*changed configuration",,,skip]'
    upsert_item(z, fw, audit, name="Firewall: configuration change events (audit: who, from where, which page/API)",
                type=7, value_type=2, delay="30s", history="90d")
    upsert_item(z, fw, f'log[{log},"noc-change",,,skip]', name="Firewall: change confirmations / reverts",
                type=7, value_type=2, delay="30s", history="90d")
    upsert_item(z, fw, f'log.count[{log},"sshd.*(Failed|Invalid user)",,,skip]',
                name="Firewall: failed SSH logins per minute", type=7, value_type=3, delay="1m")
    k_block = f'log.count[{log},"{wan_block}",,,skip]'
    k_last = "noc.fw.wan.topsrc"
    # NET-05 from the audit event (each change, with who and from where); stays open until a person matches it
    # to a change record (recovery_mode 2 = no automatic OK). Drill r1: the 2-minute hash poll missed a change
    # that reverted itself within 61 s; the hash stays as the state check (NET-05b) for changes made while
    # syslog is not arriving.
    upsert_trigger(z, fw, "NET-05-config-changed.md", priority=1, manual_close=1, recovery_mode=2,
                   description="fw1: configuration changed - match it to a change record",
                   expression=f"count(/fw1/{audit},1m)>0", opdata="{ITEM.LASTVALUE1}")
    upsert_trigger(z, fw, "NET-05-config-changed.md#hash", priority=1, manual_close=1,
                   description="fw1: running configuration differs from the last poll (SHA-256)",
                   expression="change(/fw1/noc.fw.confighash)=1")
    upsert_trigger(z, fw, "NET-06-port-scan.md", priority=3,
                   description="fw1: possible port scan from the internet ({ITEM.LASTVALUE2})",
                   # fire once the top source is known (r2 named "-": the 60 s top-source poll had not run yet)
                   expression=f'last(/fw1/{k_block})>{{$WAN.BLOCK.SCAN}} and last(/fw1/{k_last})<>"-"',
                   opdata="{ITEM.LASTVALUE1} blocked/min")
    upsert_trigger(z, fw, "NET-07-change-reverted.md", priority=4, manual_close=1,
                   description="fw1: a policy change was not confirmed and reverted itself",
                   expression=f'find(/fw1/log[{log},"noc-change",,,skip],,"like","reverted")=1')
    upsert_trigger(z, fw, "NET-08-ssh-failed.md", priority=2,
                   description="fw1: failed SSH logins ({ITEM.LASTVALUE} in the last minute)",
                   expression=f'last(/fw1/log.count[{log},"sshd.*(Failed|Invalid user)",,,skip])>=3')
    # The template looks for the process "dhcpd"; since 25.x OPNsense serves DHCP with dnsmasq, so the
    # template item is always 0 and its trigger a false alarm. Template items cannot be edited on a host:
    # disable it there and watch dnsmasq from the same SNMP process table (hrSWRunTable master item).
    dh = z.call("item.get", {"hostids": fw, "filter": {"key_": "opnsense.dhcpd.status"},
                             "output": ["itemid", "master_itemid"]})[0]
    z.call("item.update", {"itemid": dh["itemid"], "status": 1})
    for t in z.call("trigger.get", {"itemids": dh["itemid"], "output": ["triggerid"]}):
        z.call("trigger.update", {"triggerid": t["triggerid"], "status": 1})   # closes its open problem
    upsert_item(z, fw, "lab.dnsmasq.status", name="DHCP server (dnsmasq) status", type=18,
                master_itemid=dh["master_itemid"], value_type=3, valuemapid="0",
                description="hrSWRunStatus of dnsmasq: 1 running, 2 runnable, 3 not runnable, 4 invalid; 0 = absent",
                preprocessing=[{"type": 12, "params": "$[?(@.hrSWRunName == 'dnsmasq')].hrSWRunStatus.first()",
                                "error_handler": 2, "error_handler_params": "0"}])
    upsert_trigger(z, fw, "NET-09-dhcp-down.md", priority=3,
                   description="fw1: DHCP server (dnsmasq) not running",
                   expression="last(/fw1/lab.dnsmasq.status)=0 or last(/fw1/lab.dnsmasq.status)>2")
    print("hosts fw1, dmz1, lan1 configured")


if __name__ == "__main__":
    main()
