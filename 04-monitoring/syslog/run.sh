#!/usr/bin/env bash
# Build and (re)start the syslog receiver. Listens on the LAN bridge address only (10.90.10.254:5514/udp).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p ~/.local/state/noc-syslog
podman build -q -t localhost/noc-syslog:1 . >/dev/null
podman rm -f noc-syslog >/dev/null 2>&1 || true
podman run -d --name noc-syslog --restart unless-stopped --memory 64m \
  -p 10.90.10.254:5514:5514/udp -v ~/.local/state/noc-syslog:/logs:Z localhost/noc-syslog:1 >/dev/null
podman ps --filter name=noc-syslog --format '{{.Names}} {{.Status}} {{.Ports}}'
