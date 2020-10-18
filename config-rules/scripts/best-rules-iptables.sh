#!/bin/bash
# #### #### #### Best Scrip all block
echo -e $(seq -f "iptables -A INPUT -p tcp --dport %g -j DROP;" 65535) > /tmp/tcp-block-all-ports.sh
echo -e $(seq -f "iptables -A OUTPUT -p tcp --dport %g -j DROP;" 65535) >> /tmp/tcp-block-all-ports.sh
echo -e $(seq -f "iptables -A INPUT -p udp --dport %g -j DROP;" 65535) > /tmp/udp-block-all-ports.sh
echo -e $(seq -f "iptables -A OUTPUT -p udp --dport %g -j DROP;" 65535) >> /tmp/udp-block-all-ports.sh
#
echo -e $(seq -f "iptables -A INPUT -p sctp --dport %g -j DROP;" 65535) > /tmp/sctp-block-all-ports.sh
echo -e $(seq -f "iptables -A OUTPUT -p sctp --dport %g -j DROP;" 65535) >> /tmp/sctp-block-all-ports.sh
echo -e $(seq -f "iptables -A INPUT -p dccp --dport %g -j DROP;" 65535) > /tmp/dccp-block-all-ports.sh
echo -e $(seq -f "iptables -A OUTPUT -p dccp --dport %g -j DROP;" 65535) >> /tmp/dccp-block-all-ports.sh

sudo chmod +x /tmp/*-block-all-ports.sh
sudo /tmp/*-block-all-ports.sh

sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -i lo -j ACCEPT

sudo iptables -D OUTPUT -p tcp --dport 443 -j DROP
sudo iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

sudo iptables -D OUTPUT -p tcp --dport 80 -j DROP
sudo iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

sudo iptables-save -f /etc/iptables/iptables.rules
#sudo iptables-restore /etc/iptables/iptables.rules
sudo systemctl enable iptables.service
