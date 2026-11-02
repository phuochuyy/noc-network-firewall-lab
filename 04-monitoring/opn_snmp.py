"""SNMPv3 on the firewall (os-net-snmp): one read-only user with authentication and encryption, no v1/v2c
community. Who may query it is decided by the firewall policy (monitoring server only, see apply_policy.py).
Credentials from ../lab.env (SNMP_USER, SNMP_AUTH, SNMP_PRIV). Re-runnable.

usage: ~/work/tools/venvs/noc/bin/python opn_snmp.py
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "03-firewall"))
from opn import OPN, env  # noqa: E402

e = env()
o = OPN().login()
r = o.api("netsnmp/general/set", {"general": {"enabled": "1", "community": "", "syslocation": "NOC lab, rack 1",
                                              "syscontact": "noc@noc.lab", "l3visibility": "0", "versionoid": "1"}})
assert r.get("result") == "saved", r
user = {"user": {"enabled": "1", "username": e["SNMP_USER"], "password": e["SNMP_AUTH"], "enckey": e["SNMP_PRIV"],
                 "readwrite": "0"}}
rows = o.api("netsnmp/user/search_user", {})["rows"]
cur = [x for x in rows if x["username"] == e["SNMP_USER"]]
r = o.api(f"netsnmp/user/set_user/{cur[0]['uuid']}", user) if cur else o.api("netsnmp/user/add_user", user)
assert r.get("result") == "saved", r
print("reconfigure:", o.api("netsnmp/service/reconfigure", {}))
