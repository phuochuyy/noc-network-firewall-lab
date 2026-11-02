#!/usr/bin/env bash
# Firewall policy test matrix: each path tested both ways it should behave (allowed / blocked).
# Runs from the host (admin workstation on LAN), lan1 (LAN user), dmz1 (DMZ server, reached through the
# firewall as SSH jump host) and inet1 (a machine on the WAN side = internet, with a route to the DMZ range).
# IPv4 only (curl -4): the lab has no IPv6 and busybox wget picked AAAA records (run r1, 1 false FAIL).
# Output: one line per test, PASS/FAIL.
set -uo pipefail
O="-o BatchMode=yes -o ConnectTimeout=5"
LAN1="ssh $O alpine@10.90.10.10"
DMZ1="ssh $O -J root@10.90.10.1 alpine@10.90.20.10"
INET="ssh $O alpine@10.90.0.50"
pass=0 fail=0
t() {  # t <expect allow|block> <description> <command...>
  local want=$1 what=$2; shift 2
  if timeout 15 "$@" >/dev/null 2>&1; then got=allow; else got=block; fi
  if [ "$got" = "$want" ]; then pass=$((pass+1)); r=PASS; else fail=$((fail+1)); r=FAIL; fi
  printf "%s  expect %-5s got %-5s  %s\n" "$r" "$want" "$got" "$what"
}
date '+run %F %T'
t allow "LAN user  -> DMZ web :80"            $LAN1 'curl -4 -sf -m 5 -o /dev/null http://10.90.20.10/'
t block "LAN user  -> DMZ ssh :22"            $LAN1 'nc -z -w 3 10.90.20.10 22'
t allow "LAN user  -> DMZ ping"               $LAN1 'ping -c1 -W2 10.90.20.10'
t allow "LAN user  -> internet https"         $LAN1 'curl -4 -sf -m 8 -o /dev/null https://dl-cdn.alpinelinux.org/alpine/'
t allow "LAN user  -> firewall DNS"           $LAN1 'nslookup opnsense.org 10.90.10.1'
t allow "admin     -> firewall GUI (LAN)"     curl -sk -m 5 -o /dev/null https://10.90.10.1/
t allow "admin     -> DMZ web :80"            curl -s -m 5 -o /dev/null http://10.90.20.10/
t block "admin     -> DMZ ssh :22 (direct)"   bash -c 'exec 3<>/dev/tcp/10.90.20.10/22'
t block "DMZ server-> LAN user ssh :22"       $DMZ1 'nc -z -w 3 10.90.10.10 22'
t block "DMZ server-> LAN user ping"          $DMZ1 'ping -c1 -W2 10.90.10.10'
t block "DMZ server-> firewall GUI :443"      $DMZ1 'nc -z -w 3 10.90.20.1 443'
t allow "DMZ server-> firewall DNS"           $DMZ1 'nslookup opnsense.org 10.90.20.1'
t allow "DMZ server-> internet https"         $DMZ1 'curl -4 -sf -m 8 -o /dev/null https://dl-cdn.alpinelinux.org/alpine/'
t block "DMZ server-> internet ssh :22"       $DMZ1 'nc -z -w 3 1.1.1.1 22'
t allow "internet  -> published web WAN:8080" $INET 'curl -4 -sf -m 5 -o /dev/null http://10.90.0.2:8080/'
t block "internet  -> firewall GUI on WAN"    $INET 'curl -4 -sk -m 5 -o /dev/null https://10.90.0.2/'
t block "internet  -> firewall SSH on WAN"    $INET 'nc -z -w 3 10.90.0.2 22'
t block "internet  -> DMZ web :80 direct"     $INET 'curl -4 -sf -m 5 -o /dev/null http://10.90.20.10/'
t block "internet  -> DMZ ssh :22 direct"     $INET 'nc -z -w 3 10.90.20.10 22'
t block "internet  -> LAN user ping"          $INET 'ping -c1 -W2 10.90.10.10' 
echo "total: $pass PASS, $fail FAIL"
[ "$fail" -eq 0 ]
