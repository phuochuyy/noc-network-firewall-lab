"""Remote syslog from the firewall to the monitoring server (10.90.10.254:5514/udp, RFC 5424 so timestamps
carry the time zone). All programs, level info and above. Re-runnable (matched by description).

usage: ~/work/tools/venvs/noc/bin/python opn_syslog.py
"""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "03-firewall"))
from opn import OPN  # noqa: E402

DESCR = "[noc] to monitoring server"
dest = {"destination": {"enabled": "1", "transport": "udp4", "program": "",
                        "level": "info,notice,warn,err,crit,alert,emerg", "facility": "",
                        "hostname": "10.90.10.254", "port": "5514", "rfc5424": "1", "description": DESCR}}
o = OPN().login()
rows = o.api("syslog/settings/search_destinations", {})["rows"]
cur = [r for r in rows if r.get("description") == DESCR]
r = o.api(f"syslog/settings/set_destination/{cur[0]['uuid']}", dest) if cur else o.api("syslog/settings/add_destination", dest)
assert r.get("result") == "saved", r
print("reconfigure:", o.api("syslog/service/reconfigure", {}))
