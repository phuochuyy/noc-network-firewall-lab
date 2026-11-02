#!/usr/bin/env bash
# fw1: OPNsense 26.7 (nano image, FreeBSD 14) - 2 vCPU, 1 GiB RAM, 8 GiB thin disk in pool "noc".
# NIC order fixes the FreeBSD names: vtnet0 = LAN (OPNsense default LAN), vtnet1 = WAN, vtnet2 = DMZ (OPT1).
# Console: serial (virsh console fw1) + VNC on 127.0.0.1 only. Re-runnable: does nothing if fw1 exists.
set -euo pipefail
V="virsh -c qemu:///system"
$V dominfo fw1 >/dev/null 2>&1 && { echo "fw1 exists"; exit 0; }
virt-install --connect qemu:///system --name fw1 --import \
  --osinfo "${OSINFO:-freebsd14.0}" --vcpus 2 --memory 1024 \
  --disk vol=noc/fw1.qcow2,bus=virtio,discard=unmap \
  --network network=noc-lan,model=virtio,mac=52:54:00:90:10:01 \
  --network network=noc-wan,model=virtio,mac=52:54:00:90:00:02 \
  --network network=noc-dmz,model=virtio,mac=52:54:00:90:20:01 \
  --graphics vnc,listen=127.0.0.1 --console pty,target_type=serial \
  --noautoconsole   # no autostart: lab VMs on this host are started on purpose
