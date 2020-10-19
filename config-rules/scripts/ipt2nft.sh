#!/bin/bash
iptables-save > /tmp/iptables.rules
iptables-restore-translate -f /tmp/iptables.rules
iptables-restore-translate -f /tmp/iptables.rules > /tmp/ruleset.nft
nft -f /tmp/ruleset.nft
su -c "nft list ruleset > /etc/nftables.conf"
systemctl start nftables.service
systemctl enable nftables.service
nft list ruleset
