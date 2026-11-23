#!/bin/bash
# poll all candidate device addresses for web/aliveness, log transitions
for i in $(seq 1 720); do
  ts=$(date -u +%H:%M:%S)
  for ip in 192.168.32.1 192.168.0.1 192.0.0.2; do
    if ping -c1 -W1 $ip >/dev/null 2>&1; then echo "$ts ICMP-UP $ip"; fi
  done
  for ip in 192.168.32.1 192.168.0.1; do
    code=$(curl -s -m 2 -o /dev/null -w '%{http_code}' http://$ip/ 2>/dev/null)
    [ "$code" != "000" ] && echo "$ts HTTP-$code http://$ip/"
  done
  sleep 5
done
