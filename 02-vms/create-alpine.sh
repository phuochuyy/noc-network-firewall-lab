#!/usr/bin/env bash
# Small Alpine 3.24 VM from the official cloud image + a NoCloud seed (static IP, host SSH key, packages).
#   usage: [ROUTE="<net> <via>"] create-alpine.sh <name> <network> <ip/cidr> <gateway> <mac> "<apk packages>" [runcmd file]
# 1 vCPU, 256 MiB, 1 GiB thin disk in pool "noc". No autostart. Re-runnable: does nothing if the VM exists.
set -euo pipefail
name=$1 net=$2 addr=$3 gw=$4 mac=$5 pkgs=${6:-} runcmd=${7:-}
V="virsh -c qemu:///system"
IMG=~/work/tools/iso/alpine-3.24.1/generic_alpine-3.24.1-x86_64-bios-cloudinit-r0.qcow2
$V dominfo "$name" >/dev/null 2>&1 && { echo "$name exists"; exit 0; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/meta-data" <<EOF
instance-id: $name-1
local-hostname: $name
EOF
cat > "$tmp/network-config" <<EOF
version: 2
ethernets:
  eth0:
    match: {macaddress: "$mac"}
    set-name: eth0
    addresses: [$addr]
    gateway4: $gw
    nameservers: {addresses: [$gw], search: [noc.lab]}
EOF
# optional extra route: ROUTE="10.90.20.0/24 10.90.0.2" (inet1 knows the internal range, like an attacker would)
if [ -n "${ROUTE:-}" ]; then
  set -- $ROUTE
  printf '    routes:\n      - to: %s\n        via: %s\n' "$1" "$2" >> "$tmp/network-config"
fi
{
  echo "#cloud-config"
  echo "hostname: $name"
  echo "fqdn: $name.noc.lab"
  echo "timezone: Asia/Ho_Chi_Minh"
  echo "ssh_authorized_keys:"
  echo "  - $(cat ~/.ssh/id_ed25519.pub)"
  echo "ssh_pwauth: false"
  # Alpine's cloud-init does not write resolv.conf from network-config nameservers; write_files runs before
  # the package module, so apk can resolve the mirror on first boot
  echo "write_files:"
  echo "  - path: /etc/resolv.conf"
  echo "    content: |"
  echo "      search noc.lab"
  echo "      nameserver $gw"
  if [ -n "$pkgs" ]; then echo "packages: [$(echo "$pkgs" | sed 's/ /, /g')]"; fi
  if [ -n "$runcmd" ]; then echo "runcmd:"; sed 's/^/  - /' "$runcmd"; fi
} > "$tmp/user-data"
xorriso -as mkisofs -quiet -output "$tmp/seed.iso" -volid cidata -joliet -rock \
  "$tmp/user-data" "$tmp/meta-data" "$tmp/network-config"

qemu-img convert -O qcow2 "$IMG" "$tmp/disk.qcow2" && qemu-img resize -q "$tmp/disk.qcow2" 1G
$V vol-create-as noc "$name.qcow2" 1G --format qcow2 >/dev/null
$V vol-upload --pool noc "$name.qcow2" "$tmp/disk.qcow2"
$V vol-create-as noc "$name-seed.iso" 1M --format raw >/dev/null
$V vol-upload --pool noc "$name-seed.iso" "$tmp/seed.iso"

virt-install --connect qemu:///system --name "$name" --import --osinfo alpinelinux3.21 \
  --vcpus 1 --memory 256 \
  --disk vol="noc/$name.qcow2",bus=virtio,discard=unmap \
  --disk vol="noc/$name-seed.iso",device=cdrom \
  --network network="$net",model=virtio,mac="$mac" \
  --graphics none --console pty,target_type=serial --noautoconsole
