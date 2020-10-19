#!/bin/bash
iptables-save > /tmp/iptables-ruleset.txt
iptables-restore-translate -f /tmp/iptables-ruleset.txt
iptables-restore-translate -f /tmp/iptables-ruleset.txt > /tmp/ruleset.nft
nft -f /tmp/ruleset.nft
su -c "nft list ruleset > /etc/nftables.conf"
nft list ruleset
