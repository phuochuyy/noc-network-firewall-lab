"""Network fault drills: inject at T0, wait for the expected Zabbix problem (event clock), restore at T2, wait
for the recovery event. Same method as noc-monitoring-incident-lab/05-drills/mttd.py.

  link-dmz     fw1's DMZ "cable" pulled (virsh domif-setlink down)  -> published site down + SNMP link down
  web-stop     nginx stopped on dmz1                                -> published site down
  port-scan    nmap SYN scan of 1,000 ports on the WAN address      -> port-scan alert (all dropped)
  revert       a harmless policy change applied but never confirmed  -> box reverts itself after 60 s,
                                                                        change-reverted + config-changed alerts

usage: python3 net_drills.py <drill> [label]    -> ../results/net-drills-<label>.log / .jsonl
"""
import json
import pathlib
import subprocess
import sys
import time

sys.path.insert(0, str(pathlib.Path.home() / "work/noc-monitoring-incident-lab/01-stack"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "03-firewall"))
from zbx import Zabbix  # noqa: E402

RESULTS = pathlib.Path(__file__).resolve().parent.parent / "results"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
V = ["virsh", "-c", "qemu:///system"]
DMZ_MAC = "52:54:00:90:20:01"


def ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) if t else None


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw).stdout


def trig(z, host, part):
    hid = z.call("host.get", {"filter": {"host": host}, "output": ["hostid"]})[0]["hostid"]
    t = [x for x in z.call("trigger.get", {"hostids": hid, "output": ["triggerid", "description", "url"],
                                           "filter": {"status": 0}})
         if part in x["description"] or x["url"].endswith(part)]
    assert len(t) == 1, (host, part, [x["description"] for x in t])
    return t[0]["triggerid"]


def event(z, tid, since, value, timeout):
    end = time.time() + timeout
    while time.time() < end:
        ev = z.call("event.get", {"objectids": tid, "source": 0, "object": 0, "value": value,
                                  "time_from": int(since), "output": ["clock", "name"], "sortfield": ["clock"],
                                  "sortorder": "ASC", "limit": 1})
        if ev:
            return int(ev[0]["clock"]), ev[0]["name"]
        time.sleep(2)
    return None, None


def dmz_vnet():
    for line in sh(V + ["domiflist", "fw1"]).splitlines():
        if DMZ_MAC in line:
            return line.split()[0]
    raise SystemExit("DMZ interface of fw1 not found")


def run(z, name, inject, restore, watch, timeout=420, manual_close=False):
    """watch: list of (label, host, trigger part). Returns one result dict. manual_close: the triggers are
    closed by a person (change alerts) - the drill acknowledges and closes them with a note instead of
    waiting for a recovery."""
    tids = [(lab, trig(z, h, p)) for lab, h, p in watch]
    t0 = time.time()
    inject()
    det = {lab: event(z, tid, t0 - 1, 1, timeout) for lab, tid in tids}
    t2 = time.time()
    restore()
    if manual_close:
        for lab, tid in tids:
            p = z.call("problem.get", {"objectids": tid, "output": ["eventid"]})
            if p:
                z.call("event.acknowledge", {"eventids": [x["eventid"] for x in p], "action": 1 | 2 | 4,
                                             "message": f"drill {name}: expected, closed by the drill"})
    rec = {lab: (None, None) if manual_close else event(z, tid, t2 - 1, 0, timeout) for lab, tid in tids}
    out = {"drill": name, "t0": ts(t0), "t2_restore": ts(t2), "alerts": []}
    for lab, _ in tids:
        pc, pn = det[lab]
        rc, _ = rec[lab]
        out["alerts"].append({"alert": lab, "problem": ts(pc), "detect_s": round(pc - t0, 1) if pc else None,
                              "resolved": ts(rc), "resolve_s": round(rc - t2, 1) if rc else None, "name": pn})
    return out


def link_dmz(z):
    nic = dmz_vnet()
    return run(z, "link-dmz",
               lambda: sh(V + ["domif-setlink", "fw1", nic, "down"]),
               lambda: sh(V + ["domif-setlink", "fw1", nic, "up"]),
               [("published site down", "dmz1", "NET-03-web-down.md"),
                ("SNMP link down vtnet2", "fw1", "Interface [vtnet2()]: Link down")])


def web_stop(z):
    dmz = SSH + ["-J", "root@10.90.10.1", "alpine@10.90.20.10"]
    return run(z, "web-stop",
               lambda: sh(dmz + ["doas rc-service nginx stop"]),
               lambda: sh(dmz + ["doas rc-service nginx start"]),
               [("published site down", "dmz1", "NET-03-web-down.md")])


def port_scan(z):
    inet = SSH + ["alpine@10.90.0.50"]
    out = {}

    def scan():
        r = subprocess.run(inet + ["doas nmap -sS -Pn -T4 -p 1-1000 10.90.0.2 -oG - | grep -E 'Ports:|Status'"],
                           capture_output=True, text=True)
        out["nmap"] = r.stdout.strip()[-400:]
    res = run(z, "port-scan", scan, lambda: None, [("port scan alert", "fw1", "NET-06-port-scan.md")])
    res["nmap_open_ports"] = out.get("nmap", "")
    return res


def revert(z):
    from opn import OPN
    o = OPN().login()
    rule = [r for r in o.api("firewall/filter/search_rule", {"rowCount": -1})["rows"]
            if r["description"] == "[noc] DMZ ping out"][0]
    fw = SSH + ["root@10.90.10.1"]
    arm = ("cp /conf/config.xml /tmp/noc-rollback.xml && touch /tmp/noc-rollback.armed && "
           "(sleep 60; if [ -f /tmp/noc-rollback.armed ]; then cp /tmp/noc-rollback.xml /conf/config.xml && "
           "configctl filter reload && logger -t noc-change 'policy change reverted (not confirmed)'; fi) "
           ">/dev/null 2>&1 &")

    def change():  # arm, then a harmless change (turn logging on for one rule), applied, never confirmed
        sh(fw + [f'sh -c "{arm}"'])
        o.api(f"firewall/filter/toggle_rule_log/{rule['uuid']}/1", {})
        o.api("firewall/filter/apply", {})

    res = run(z, "revert (unconfirmed change)", change, lambda: None,
              [("change reverted", "fw1", "NET-07-change-reverted.md"),
               ("config changed", "fw1", "NET-05-config-changed.md")], timeout=300, manual_close=True)
    res["note"] = "detect_s is measured from the change (T0); the box reverts 60 s after arming"
    return res


DRILLS = {"link-dmz": link_dmz, "web-stop": web_stop, "port-scan": port_scan, "revert": revert}


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else ""
    label = sys.argv[2] if len(sys.argv) > 2 else "r1"
    if name not in DRILLS:
        sys.exit(f"usage: net_drills.py <{'|'.join(DRILLS)}> [label]")
    z = Zabbix.from_env()
    res = DRILLS[name](z)
    RESULTS.mkdir(exist_ok=True)
    with (RESULTS / f"net-drills-{label}.jsonl").open("a") as f:
        f.write(json.dumps(res) + "\n")
    with (RESULTS / f"net-drills-{label}.log").open("a") as f:
        for a in res["alerts"]:
            line = (f"{res['drill']}: fault {res['t0']} | {a['alert']}: problem {a['problem']} (+{a['detect_s']} s)"
                    f" | restored {res['t2_restore']} | resolved {a['resolved']} (+{a['resolve_s']} s)")
            print(line)
            f.write(line + "\n")
        if res.get("nmap_open_ports") is not None:
            f.write(f"  nmap: {res['nmap_open_ports']}\n")
            print("  nmap:", res["nmap_open_ports"])


if __name__ == "__main__":
    main()
