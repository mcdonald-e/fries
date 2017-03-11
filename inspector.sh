#!/bin/sh
# script to monitor for attacks

while true
clear
do
  iptables -nvL INPUT > /tmp/now
  tail -n 15 /tmp/now; sleep 10; clear
  /usr/local/ddos/ddos.sh -v; sleep 5; clear
  tail /var/log/messages |
    sed -e 's/\(SRC=[0-9]*.[0-9]*.[0-9]*.[0-9]*\)/\o033[34m\1\o033[0m/g' \
    -e 's/\(DST=[0-9]*.[0-9]*.[0-9]*.[0-9]*\)/\o033[31m\1\o033[0m/g' \
    -e 's/\(SPT=[0-9]*\)/\o033[32m\1\o033[0m/g' \
    -e 's/\(DPT=[0-9]*\)/\o033[33m\1\o033[0m/g'; sleep 10; clear
  /bin/procmon.sh; sleep 5; clear
done
