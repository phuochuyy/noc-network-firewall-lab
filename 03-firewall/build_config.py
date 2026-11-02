"""Turn the factory config.xml of a new OPNsense 26.7 into the lab's base configuration.

Base only (system, interfaces, DHCP, SSH, port forward); firewall rules and syslog are applied through the API
by apply_policy.py so they are validated by OPNsense's own models.

  WAN  vtnet1  DHCP from libvirt NAT (10.90.0.2 reserved)    "internet"
  LAN  vtnet0  10.90.10.1/24, DHCP .100-.199                 users, admin workstation (host .254)
  DMZ  vtnet2  10.90.20.1/24, static servers                 published web server 10.90.20.10

The output holds the GUI certificate's private key and password hashes: never commit it.
usage: ~/work/tools/venvs/noc/bin/python build_config.py <factory.xml> <out.xml>
"""
import base64
import pathlib
import sys
import xml.etree.ElementTree as ET

import bcrypt

ENV = pathlib.Path(__file__).resolve().parent.parent / "lab.env"
PUBKEY = pathlib.Path.home() / ".ssh/id_ed25519.pub"


def env():
    out = {}
    for line in ENV.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def setv(parent, tag, value):
    el = parent.find(tag)
    if el is None:
        el = ET.SubElement(parent, tag)
    el.text = value
    return el


def drop(parent, *tags):
    for t in tags:
        for el in parent.findall(t):
            parent.remove(el)


def main(src, dst):
    e = env()
    tree = ET.parse(src)
    r = tree.getroot()
    drop(r, "trigger_initial_wizard")

    s = r.find("system")
    setv(s, "hostname", "fw1")
    setv(s, "domain", "noc.lab")
    setv(s, "timezone", "Asia/Ho_Chi_Minh")
    root = [u for u in s.findall("user") if u.findtext("name") == "root"][0]
    # bcrypt ($2y$, like the factory hash); the clear text lives only in lab.env
    h = bcrypt.hashpw(e["OPN_ROOT_PASSWORD"].encode(), bcrypt.gensalt(rounds=11)).decode().replace("$2b$", "$2y$", 1)
    setv(root, "password", h)
    setv(root, "authorizedkeys", base64.b64encode(PUBKEY.read_bytes().strip() + b"\n").decode())
    ssh = s.find("ssh")
    setv(ssh, "enabled", "enabled")
    setv(ssh, "permitrootlogin", "1")       # key only: passwordauth is not set
    setv(ssh, "interfaces", "lan")          # sshd listens on LAN only

    ifs = r.find("interfaces")
    wan, lan = ifs.find("wan"), ifs.find("lan")
    setv(wan, "blockpriv", "")              # the lab "internet" is 10.90.0.0/24 (private)
    setv(wan, "ipaddrv6", "")
    setv(lan, "ipaddr", "10.90.10.1")
    setv(lan, "subnet", "24")
    setv(lan, "ipaddrv6", "")
    drop(lan, "subnetv6", "track6-interface", "track6-prefix-id")
    drop(ifs, "opt1")
    dmz = ET.SubElement(ifs, "opt1")
    for k, v in [("enable", "1"), ("if", "vtnet2"), ("descr", "DMZ"), ("ipaddr", "10.90.20.1"), ("subnet", "24"),
                 ("spoofmac", ""), ("blockpriv", ""), ("blockbogons", "")]:
        setv(dmz, k, v)

    rng = r.find("dnsmasq/dhcp_ranges")
    setv(rng, "start_addr", "10.90.10.100")
    setv(rng, "end_addr", "10.90.10.199")

    # publish the DMZ web server: WAN :8080 -> 10.90.20.10:80, with an associated pass rule
    nat = r.find("nat")
    drop(nat, "rule")
    pf = ET.SubElement(nat, "rule")
    src_el = ET.SubElement(pf, "source")
    ET.SubElement(src_el, "any").text = "1"
    dst_el = ET.SubElement(pf, "destination")
    ET.SubElement(dst_el, "network").text = "wanip"
    ET.SubElement(dst_el, "port").text = "8080"
    for k, v in [("protocol", "tcp"), ("target", "10.90.20.10"), ("local-port", "80"), ("interface", "wan"),
                 ("ipprotocol", "inet"), ("descr", "[noc] publish DMZ web (WAN 8080 -> dmz1:80)"),
                 ("associated-rule-id", "pass")]:
        setv(pf, k, v)

    ET.indent(tree, "  ")
    tree.write(dst, encoding="unicode", xml_declaration=True)
    print(f"wrote {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
