#!/usr/bin/env bash
set -euo pipefail

modprobe br_netfilter
sysctl -w net.bridge.bridge-nf-call-iptables=1

iptables -A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A DOCKER-USER -p tcp -s 172.30.0.10 -d 172.30.0.40 --dport 8000 -j ACCEPT
iptables -A DOCKER-USER -p tcp -s 172.30.0.10 -d 172.30.0.66 --dport 8080 -j LOG --log-prefix "HW4-C2-DROP: "
iptables -A DOCKER-USER -p tcp -s 172.30.0.10 -d 172.30.0.66 --dport 8080 -j DROP
iptables -A DOCKER-USER -s 172.30.0.10 -m conntrack --ctstate NEW -j DROP
iptables -A DOCKER-USER -j RETURN
