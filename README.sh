# #   ##-##   sudo pacman -S nftables iptables-nft fail2ban

#!/bin/bash

# #### #### #### Example 1
# iptables -A INPUT -p tcp -m tcp -m multiport ! --dports 80,443 -j DROP
# iptables -A INPUT -p tcp -m tcp -m multiport --dports 80,443 -j ACCEPT
# iptables -A INPUT -m conntrack -j ACCEPT  --ctstate RELATED,ESTABLISHED
# iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# iptables -A INPUT -j DROP
# iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# iptables -A OUTPUT -j DROP
# iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
# iptables -A FORWARD -j DROP
#
# #### #### #### Script Clear 1
# Remove all DROPs.
# iptables="/sbin/iptables"
# echo "[*] Removing all DROPs ..."
# IFS_OLD=$IFS
# IFS=$'\n'
# rule_list=$(${iptables} -S | grep 'DROP$')
# for drop_rule in ${rule_list}; do
#     undrop_rule=$(printf -- "${drop_rule}\n" | sed 's@^-A@-D@')
#     printf "[-] ${iptables} ${undrop_rule}\n"
#
#     ${iptables} -v ${undrop_rule}
#     [ $? == 1 ] && echo "[E] Unable to delete DROP rule." && exit 1
# done
# IFS=$IFS_OLD
# printf '\n\n'
# ${iptables} -S
#
# Clear Method 2
# iptables -F
# iptables -X
#
# Clear Method 3
# iptables -F
# iptables -X
# iptables -t nat -F
# iptables -t nat -X
# iptables -t mangle -F
# iptables -t mangle -X
# iptables -P INPUT ACCEPT
# iptables -P FORWARD ACCEPT
# iptables -P OUTPUT ACCEPT
#
##### Clear manually the command:
# iptables -D INPUT -s 209.126.1.2/32 -i eth0 -j DROP
#
##### List all rules
# iptables -L -n -v
#
# #### #### #### Print all rules in the selected chain.
# iptables -S

# -P {chain} {target} 	Set the policy for the built-in chain to either ACCEPT or DROP.
# -t {table} 	State the packet matching table which the command should operate on. The tables are filter, nat, mangle, raw, and security.
# -S 	Print all rules in the selected chain.
# -L 	List all rules in the selected chain.
# -n 	Disable DNS lookups and speed up listing option.
# -v 	Verbose firewall output. This option makes the list command show the interface name, the rule options (if any), and the TOS masks. The packet and byte counters are also listed. For appending, insertion, deletion and replacement, this causes detailed information on the rule or rules to be printed. -v may be specified multiple times to possibly emit more detailed debug statements.
# -F 	Flush the selected chain and firewall rules.
# -Z 	Zero the packet and byte counters in all chains, or only the given chain, or only the given rule in a chain.
# -X 	Delete the optional user-defined chain specified. If no argument is given, it will attempt to delete every non-builtin chain in the table.

# #### #### #### --help
# Usage: iptables -[ACD] chain rule-specification [options]
#       iptables -I chain [rulenum] rule-specification [options]
#       iptables -R chain rulenum rule-specification [options]
#       iptables -D chain rulenum [options]
#       iptables -[LS] [chain [rulenum]] [options]
#       iptables -[FZ] [chain] [options]
#       iptables -[NX] chain
#       iptables -E old-chain-name new-chain-name
#       iptables -P chain target [options]
#       iptables -h (print this help information)
#
# Commands:
# Either long or short options are allowed.
#  --append  -A chain		Append to chain
#  --check   -C chain		Check for the existence of a rule
#  --delete  -D chain		Delete matching rule from chain
#  --delete  -D chain rulenum
#				Delete rule rulenum (1 = first) from chain
#  --insert  -I chain [rulenum]
#				Insert in chain as rulenum (default 1=first)
#  --replace -R chain rulenum
#				Replace rule rulenum (1 = first) in chain
#  --list    -L [chain [rulenum]]
#				List the rules in a chain or all chains
#  --list-rules -S [chain [rulenum]]
#				Print the rules in a chain or all chains
#  --flush   -F [chain]		Delete all rules in  chain or all chains
#  --zero    -Z [chain [rulenum]]
#				Zero counters in chain or all chains
#  --new     -N chain		Create a new user-defined chain
#  --delete-chain
#            -X [chain]		Delete a user-defined chain
#  --policy  -P chain target
#				Change policy on chain to target
#  --rename-chain
#            -E old-chain new-chain
#				Change chain name, (moving any references)
# Options:
#  --ipv4	-4		Nothing (line is ignored by ip6tables-restore)
#  --ipv6	-6		Error (line is ignored by iptables-restore)
#  --protocol	-p proto	protocol: by number or name, eg. `tcp'
#  --source	-s address[/mask][...]
#				source specification
#  --destination -d address[/mask][...]
#				destination specification
#  --in-interface -i input name[+]
#				network interface name ([+] for wildcard)
#  --jump	-j target
#				target for rule (may load target extension)
#  --goto      -g chain
#                               jump to chain with no return
#  --match	-m match
#				extended match (may load extension)
#  --numeric	-n		numeric output of addresses and ports
#  --out-interface -o output name[+]
#				network interface name ([+] for wildcard)
#  --table	-t table	table to manipulate (default: `filter')
#  --verbose	-v		verbose mode
#  --wait	-w [seconds]	maximum wait to acquire xtables lock before give up
#  --wait-interval -W [usecs]	wait time to try to acquire xtables lock
#				default is 1 second
#  --line-numbers		print line numbers when listing
#  --exact	-x		expand numbers (display exact values)
#  --fragment	-f		match second or further fragments only
#  --modprobe=<command>		try to insert modules using this command
#  --set-counters PKTS BYTES	set the counter during insert/append
#  --version	-V		print package version.
#
# #### #### #### Rule example 1
#
# *filter
# :INPUT ACCEPT [0:0]
# :FORWARD ACCEPT [0:0]
# :OUTPUT ACCEPT [0:0]
# :RH-Firewall-1-INPUT - [0:0]
# -A INPUT -j RH-Firewall-1-INPUT
# -A FORWARD -j RH-Firewall-1-INPUT
# -A RH-Firewall-1-INPUT -i lo -j ACCEPT
# -A RH-Firewall-1-INPUT -p icmp --icmp-type any -j ACCEPT
# -A RH-Firewall-1-INPUT -p 50 -j ACCEPT
# -A RH-Firewall-1-INPUT -p 51 -j ACCEPT
# -A RH-Firewall-1-INPUT -p udp --dport 5353 -d 224.0.0.251 -j ACCEPT
# -A RH-Firewall-1-INPUT -p udp -m udp --dport 631 -j ACCEPT
# -A RH-Firewall-1-INPUT -p tcp -m tcp --dport 631 -j ACCEPT
# -A RH-Firewall-1-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# -A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
# -A RH-Firewall-1-INPUT -j REJECT --reject-with icmp-host-prohibited
#
#           #### Example 2
# Setting default policies:
# iptables -P INPUT DROP
# iptables -P FORWARD DROP
# iptables -P OUTPUT ACCEPT
#
# Exceptions to default policy
# iptables -A INPUT -p tcp --dport 80 -j ACCEPT       # HTTP
# iptables -A INPUT -p tcp --dport 443 -j ACCEPT      # HTTPS
#
#           #### Example 3
# iptables -P INPUT ACCEPT
# iptables -P FORWARD ACCEPT
# iptables -P OUTPUT ACCEPT
# iptables -A FORWARD -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
#
#                         #################################
#                         #### Nftables equivalent commands
#
#            https://www.redhat.com/en/blog/using-iptables-nft-hybrid-linux-firewall
#            https://wiki.nftables.org/wiki-nftables/index.php/Moving_from_iptables_to_nftables
#            https://wiki.nftables.org/wiki-nftables/index.php/Quick_reference-nftables_in_10_minutes
#            https://xdeb.org/post/2019/09/26/setting-up-a-server-firewall-with-nftables-that-support-wireguard-vpn/
#            https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_server
#            https://manpages.debian.org/buster-backports/nftables/nftables.8.en.html
#            https://workaround.org/ispmail/buster/firewalling-and-brute-force-mitigation/
#            https://debian-handbook.info/browse/pt-BR/stable/sect.firewall-packet-filtering.html
#            https://wiki.archlinux.org/index.php/Simple_stateful_firewall
#            https://www.digitalocean.com/community/tutorials/how-to-list-and-delete-iptables-firewall-rules
#            https://www.casbay.com/guide/kb/how-to-block-all-ports-in-iptables/                                <-- best rules
#
# iptables-translate -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
# nft add rule ip filter INPUT tcp dport 22 ct state new counter accept
#
# ip6tables-translate -A FORWARD -i eth0 -o eth3 -p udp -m multiport --dports 111,222 -j ACCEPT
# nft add rule ip6 filter FORWARD iifname eth0 oifname eth3 meta l4proto udp udp dport { 111,222} counter accept
#
# iptables-nft -A INPUT -i eth0 -s 10.0.0.0/8 -j ACCEPT
# nft add rule ip filter INPUT meta iifname "eth0" ip saddr 10.0.0.0/8 counter accept
#
# iptables-nft -A FORWARD -p icmp -j ACCEPT
#
# iptables save
# nft list tables
# nft list table filter
#
# iptables -L -n -v
# nft list ruleset
#
# iptables -A INPUT -i eth0 -m mac ! --mac-source 00:00:5e:00:53:00 -j DROP
# nft add rule filter input iif eth0 ether saddr != 00:00:5e:00:53:00 drop
#
# iptables -A OUTPUT -p tcp -m tcp -d www.xvideos.com -j DROP
# meta l4proto tcp ip daddr 185.88.181.0/24 drop
# ip6tables -A OUTPUT -p tcp -m tcp -d google.fr -j DROP
# meta l4proto tcp ip6 daddr 2800:3f0:4004:800::2003 drop
# meta l4proto tcp ip6 daddr 2800:3f0:4004:800::/128 drop
#
#              Moving from iptables to nftables
#              --------------------------------
# iptables-save > iptables.rules
# iptables-restore-translate -f iptables.rules
# iptables-restore-translate -f iptables.rules > ruleset.nft
# nft -f ruleset.nft
# nft list ruleset

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

################################################################################################
# https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml #
# https://pt.wikipedia.org/wiki/Lista_de_portas_dos_protocolos_TCP_e_UDP#Portas_49152_a_65535  #
#                From 49152 to 65535 can be used dynamically by applications                   #
#           https://www.sciencedirect.com/topics/computer-science/registered-port              #
###### -----                        ----- ################## --------- ################## - ####
######       Script Block all ports       ################## --------- ################## - ####
# -------------------------------------------------------------------------------------------- #

# Reserved
iptables -A INPUT -p tcp --dport 0 -j DROP          # Reserved - tcp
iptables -A OUTPUT -p tcp --dport 0 -j DROP         # Reserved - tcp
iptables -A INPUT -p udp --dport 0 -j DROP          # Reserved - udp
iptables -A OUTPUT -p udp --dport 0 -j DROP         # Reserved - udp
iptables -A INPUT -p sctp --dport 0 -j DROP         # Reserved - sctp
iptables -A OUTPUT -p sctp --dport 0 -j DROP        # Reserved - sctp
iptables -A INPUT -p dccp --dport 0 -j DROP         # Reserved - dccp
iptables -A OUTPUT -p dccp --dport 0 -j DROP        # Reserved - dccp

# TCP Port Service Multiplexer
iptables -A INPUT -p tcp --dport 1 -j DROP          # tcpmux - tcp
iptables -A OUTPUT -p tcp --dport 1 -j DROP         # tcpmux - tcp
iptables -A INPUT -p udp --dport 1 -j DROP          # tcpmux - udp
iptables -A OUTPUT -p udp --dport 1 -j DROP         # tcpmux - udp
iptables -A INPUT -p sctp --dport 1 -j DROP         # tcpmux - sctp
iptables -A OUTPUT -p sctp --dport 1 -j DROP        # tcpmux - sctp
iptables -A INPUT -p dccp --dport 1 -j DROP         # tcpmux - dccp
iptables -A OUTPUT -p dccp --dport 1 -j DROP        # tcpmux - dccp

# Management Utility
iptables -A INPUT -p tcp --dport 2 -j DROP          # compressnet - tcp
iptables -A OUTPUT -p tcp --dport 2 -j DROP         # compressnet - tcp
iptables -A INPUT -p udp --dport 2 -j DROP          # compressnet - udp
iptables -A OUTPUT -p udp --dport 2 -j DROP         # compressnet - udp
iptables -A INPUT -p sctp --dport 2 -j DROP         # compressnet - sctp
iptables -A OUTPUT -p sctp --dport 2 -j DROP        # compressnet - sctp
iptables -A INPUT -p dccp --dport 2 -j DROP         # compressnet - dccp
iptables -A OUTPUT -p dccp --dport 2 -j DROP        # compressnet - dccp

# Compression Process
iptables -A INPUT -p tcp --dport 3 -j DROP          # compressnet - tcp
iptables -A OUTPUT -p tcp --dport 3 -j DROP         # compressnet - tcp
iptables -A INPUT -p udp --dport 3 -j DROP          # compressnet - udp
iptables -A OUTPUT -p udp --dport 3 -j DROP         # compressnet - udp
iptables -A INPUT -p sctp --dport 3 -j DROP         # compressnet - sctp
iptables -A OUTPUT -p sctp --dport 3 -j DROP        # compressnet - sctp
iptables -A INPUT -p dccp --dport 3 -j DROP         # compressnet - dccp
iptables -A OUTPUT -p dccp --dport 3 -j DROP        # compressnet - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 4 -j DROP          # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 4 -j DROP         # Unassigned - tcp
iptables -A INPUT -p udp --dport 4 -j DROP          # Unassigned - udp
iptables -A OUTPUT -p udp --dport 4 -j DROP         # Unassigned - udp
iptables -A INPUT -p sctp --dport 4 -j DROP         # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 4 -j DROP        # Unassigned - sctp
iptables -A INPUT -p dccp --dport 4 -j DROP         # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 4 -j DROP        # Unassigned - dccp

# Remote Job Entry
iptables -A INPUT -p tcp --dport 5 -j DROP          # rje - tcp
iptables -A OUTPUT -p tcp --dport 5 -j DROP         # rje - tcp
iptables -A INPUT -p udp --dport 5 -j DROP          # rje - udp
iptables -A OUTPUT -p udp --dport 5 -j DROP         # rje - udp
iptables -A INPUT -p sctp --dport 5 -j DROP         # rje - sctp
iptables -A OUTPUT -p sctp --dport 5 -j DROP        # rje - sctp
iptables -A INPUT -p dccp --dport 5 -j DROP         # rje - dccp
iptables -A OUTPUT -p dccp --dport 5 -j DROP        # rje - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 6 -j DROP          # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 6 -j DROP         # Unassigned - tcp
iptables -A INPUT -p udp --dport 6 -j DROP          # Unassigned - udp
iptables -A OUTPUT -p udp --dport 6 -j DROP         # Unassigned - udp
iptables -A INPUT -p sctp --dport 6 -j DROP         # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 6 -j DROP        # Unassigned - sctp
iptables -A INPUT -p dccp --dport 6 -j DROP         # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 6 -j DROP        # Unassigned - dccp

# Echo
iptables -A INPUT -p tcp --dport 7 -j DROP          # Echo - tcp
iptables -A OUTPUT -p tcp --dport 7 -j DROP         # Echo - tcp
iptables -A INPUT -p udp --dport 7 -j DROP          # Echo - udp
iptables -A OUTPUT -p udp --dport 7 -j DROP         # Echo - udp
iptables -A INPUT -p sctp --dport 7 -j DROP         # Echo - sctp
iptables -A OUTPUT -p sctp --dport 7 -j DROP        # Echo - sctp
iptables -A INPUT -p dccp --dport 7 -j DROP         # Echo - dccp
iptables -A OUTPUT -p dccp --dport 7 -j DROP        # Echo - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 8 -j DROP          # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 8 -j DROP         # Unassigned - tcp
iptables -A INPUT -p udp --dport 8 -j DROP          # Unassigned - udp
iptables -A OUTPUT -p udp --dport 8 -j DROP         # Unassigned - udp
iptables -A INPUT -p sctp --dport 8 -j DROP         # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 8 -j DROP        # Unassigned - sctp
iptables -A INPUT -p dccp --dport 8 -j DROP         # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 8 -j DROP        # Unassigned - dccp

# Discard
iptables -A INPUT -p tcp --dport 9 -j DROP          # Discard - tcp
iptables -A OUTPUT -p tcp --dport 9 -j DROP         # Discard - tcp
iptables -A INPUT -p udp --dport 9 -j DROP          # Discard - udp
iptables -A OUTPUT -p udp --dport 9 -j DROP         # Discard - udp
iptables -A INPUT -p sctp --dport 9 -j DROP         # Discard - sctp
iptables -A OUTPUT -p sctp --dport 9 -j DROP        # Discard - sctp
iptables -A INPUT -p dccp --dport 9 -j DROP         # Discard - sctp
iptables -A OUTPUT -p dccp --dport 9 -j DROP        # Discard - sctp

# Unassigned
iptables -A INPUT -p tcp --dport 10 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 10 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 10 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 10 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 10 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 10 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 10 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 10 -j DROP       # Unassigned - dccp

# Active Users
iptables -A INPUT -p tcp --dport 11 -j DROP         # systat - tcp
iptables -A OUTPUT -p tcp --dport 11 -j DROP        # systat - tcp
iptables -A INPUT -p udp --dport 11 -j DROP         # systat - udp
iptables -A OUTPUT -p udp --dport 11 -j DROP        # systat - udp
iptables -A INPUT -p sctp --dport 11 -j DROP        # systat - sctp
iptables -A OUTPUT -p sctp --dport 11 -j DROP       # systat - sctp
iptables -A INPUT -p dccp --dport 11 -j DROP        # systat - dccp
iptables -A OUTPUT -p dccp --dport 11 -j DROP       # systat - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 12 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 12 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 12 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 12 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 12 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 12 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 12 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 12 -j DROP       # Unassigned - dccp

# Daytime
iptables -A INPUT -p tcp --dport 13 -j DROP         # Daytime - tcp
iptables -A OUTPUT -p tcp --dport 13 -j DROP        # Daytime - tcp
iptables -A INPUT -p udp --dport 13 -j DROP         # Daytime - udp
iptables -A OUTPUT -p udp --dport 13 -j DROP        # Daytime - udp
iptables -A INPUT -p sctp --dport 13 -j DROP        # Daytime - sctp
iptables -A OUTPUT -p sctp --dport 13 -j DROP       # Daytime - sctp
iptables -A INPUT -p dccp --dport 13 -j DROP        # Daytime - dccp
iptables -A OUTPUT -p dccp --dport 13 -j DROP       # Daytime - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 14 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 14 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 14 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 14 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 14 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 14 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 14 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 14 -j DROP       # Unassigned - dccp

# Unassigned [was netstat]
iptables -A INPUT -p tcp --dport 15 -j DROP         # Unassigned [was netstat] - tcp
iptables -A OUTPUT -p tcp --dport 15 -j DROP        # Unassigned [was netstat] - tcp
iptables -A INPUT -p udp --dport 15 -j DROP         # Unassigned [was netstat] - udp
iptables -A OUTPUT -p udp --dport 15 -j DROP        # Unassigned [was netstat] - udp
iptables -A INPUT -p sctp --dport 15 -j DROP        # Unassigned [was netstat] - sctp
iptables -A OUTPUT -p sctp --dport 15 -j DROP       # Unassigned [was netstat] - sctp
iptables -A INPUT -p dccp --dport 15 -j DROP        # Unassigned [was netstat] - dccp
iptables -A OUTPUT -p dccp --dport 15 -j DROP       # Unassigned [was netstat] - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 16 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 16 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 16 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 16 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 16 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 16 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 16 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 16 -j DROP       # Unassigned - dccp

# Quote of the Day
iptables -A INPUT -p tcp --dport 17 -j DROP         # qotd - tcp
iptables -A OUTPUT -p tcp --dport 17 -j DROP        # qotd - tcp
iptables -A INPUT -p udp --dport 17 -j DROP         # qotd - udp
iptables -A OUTPUT -p udp --dport 17 -j DROP        # qotd - udp
iptables -A INPUT -p sctp --dport 17 -j DROP        # qotd - sctp
iptables -A OUTPUT -p sctp --dport 17 -j DROP       # qotd - sctp
iptables -A INPUT -p dccp --dport 17 -j DROP        # qotd - dccp
iptables -A OUTPUT -p dccp --dport 17 -j DROP       # qotd - dccp

# Message Send Protocol (historic)
iptables -A INPUT -p tcp --dport 18 -j DROP         # msp - tcp
iptables -A OUTPUT -p tcp --dport 18 -j DROP        # msp - tcp
iptables -A INPUT -p udp --dport 18 -j DROP         # msp - udp
iptables -A OUTPUT -p udp --dport 18 -j DROP        # msp - udp
iptables -A INPUT -p sctp --dport 18 -j DROP        # msp - sctp
iptables -A OUTPUT -p sctp --dport 18 -j DROP       # msp - sctp
iptables -A INPUT -p dccp --dport 18 -j DROP        # msp - dccp
iptables -A OUTPUT -p dccp --dport 18 -j DROP       # msp - dccp

# Character Generator
iptables -A INPUT -p tcp --dport 19 -j DROP         # chargen - tcp
iptables -A OUTPUT -p tcp --dport 19 -j DROP        # chargen - tcp
iptables -A INPUT -p udp --dport 19 -j DROP         # chargen - udp
iptables -A OUTPUT -p udp --dport 19 -j DROP        # chargen - udp
iptables -A INPUT -p sctp --dport 19 -j DROP        # chargen - sctp
iptables -A OUTPUT -p sctp --dport 19 -j DROP       # chargen - sctp
iptables -A INPUT -p dccp --dport 19 -j DROP        # chargen - dccp
iptables -A OUTPUT -p dccp --dport 19 -j DROP       # chargen - dccp

# File Transfer [Default Data]
iptables -A INPUT -p tcp --dport 20 -j DROP         # ftp-data - tcp
iptables -A OUTPUT -p tcp --dport 20 -j DROP        # ftp-data - tcp
iptables -A INPUT -p udp --dport 20 -j DROP         # ftp-data - udp
iptables -A OUTPUT -p udp --dport 20 -j DROP        # ftp-data - udp
iptables -A INPUT -p sctp --dport 20 -j DROP        # ftp-data - sctp
iptables -A OUTPUT -p sctp --dport 20 -j DROP       # ftp-data - sctp
iptables -A INPUT -p dccp --dport 20 -j DROP        # ftp-data - dccp
iptables -A OUTPUT -p dccp --dport 20 -j DROP       # ftp-data - dccp

# File Transfer [Default Data]
iptables -A INPUT -p tcp --dport 21 -j DROP         # ftp-data - tcp
iptables -A OUTPUT -p tcp --dport 21 -j DROP        # ftp-data - tcp
iptables -A INPUT -p udp --dport 21 -j DROP         # ftp-data - udp
iptables -A OUTPUT -p udp --dport 21 -j DROP        # ftp-data - udp
iptables -A INPUT -p sctp --dport 21 -j DROP        # ftp-data - sctp
iptables -A OUTPUT -p sctp --dport 21 -j DROP       # ftp-data - sctp
iptables -A INPUT -p dccp --dport 21 -j DROP        # ftp-data - dccp
iptables -A OUTPUT -p dccp --dport 21 -j DROP       # ftp-data - dccp

# The Secure Shell (SSH) Protocol
iptables -A INPUT -p tcp --dport 22 -j DROP         # SSH - tcp
iptables -A OUTPUT -p tcp --dport 22 -j DROP        # SSH - tcp
iptables -A INPUT -p udp --dport 22 -j DROP         # SSH - udp
iptables -A OUTPUT -p udp --dport 22 -j DROP        # SSH - udp
iptables -A INPUT -p sctp --dport 22 -j DROP        # SSH - sctp
iptables -A OUTPUT -p sctp --dport 22 -j DROP       # SSH - sctp
iptables -A INPUT -p dccp --dport 22 -j DROP        # SSH - dccp
iptables -A OUTPUT -p dccp --dport 22 -j DROP       # SSH - dccp

# Telnet
iptables -A INPUT -p tcp --dport 23 -j DROP         # Telnet - tcp
iptables -A OUTPUT -p tcp --dport 23 -j DROP        # Telnet - tcp
iptables -A INPUT -p udp --dport 23 -j DROP         # Telnet - udp
iptables -A OUTPUT -p udp --dport 23 -j DROP        # Telnet - udp
iptables -A INPUT -p sctp --dport 23 -j DROP        # Telnet - sctp
iptables -A OUTPUT -p sctp --dport 23 -j DROP       # Telnet - sctp
iptables -A INPUT -p dccp --dport 23 -j DROP        # Telnet - dccp
iptables -A OUTPUT -p dccp --dport 23 -j DROP       # Telnet - dccp

# Any private mail system
iptables -A INPUT -p tcp --dport 24 -j DROP         # any private mail system - tcp
iptables -A OUTPUT -p tcp --dport 24 -j DROP        # any private mail system - tcp
iptables -A INPUT -p udp --dport 24 -j DROP         # any private mail system - udp
iptables -A OUTPUT -p udp --dport 24 -j DROP        # any private mail system - udp
iptables -A INPUT -p sctp --dport 24 -j DROP        # any private mail system - sctp
iptables -A OUTPUT -p sctp --dport 24 -j DROP       # any private mail system - sctp
iptables -A INPUT -p dccp --dport 24 -j DROP        # any private mail system - dccp
iptables -A OUTPUT -p dccp --dport 24 -j DROP       # any private mail system - dccp

# Simple Mail Transfer
iptables -A INPUT -p tcp --dport 25 -j DROP         # smtp - tcp
iptables -A OUTPUT -p tcp --dport 25 -j DROP        # smtp - tcp
iptables -A INPUT -p udp --dport 25 -j DROP         # smtp - udp
iptables -A OUTPUT -p udp --dport 25 -j DROP        # smtp - udp
iptables -A INPUT -p sctp --dport 25 -j DROP        # smtp - sctp
iptables -A OUTPUT -p sctp --dport 25 -j DROP       # smtp - sctp
iptables -A INPUT -p dccp --dport 25 -j DROP        # smtp - dccp
iptables -A OUTPUT -p dccp --dport 25 -j DROP       # smtp - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 26 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 26 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 26 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 26 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 26 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 26 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 26 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 26 -j DROP       # Unassigned - dccp

# NSW User System FE
iptables -A INPUT -p tcp --dport 27 -j DROP         # nsw-fe - tcp
iptables -A OUTPUT -p tcp --dport 27 -j DROP        # nsw-fe - tcp
iptables -A INPUT -p udp --dport 27 -j DROP         # nsw-fe - udp
iptables -A OUTPUT -p udp --dport 27 -j DROP        # nsw-fe - udp
iptables -A INPUT -p sctp --dport 27 -j DROP        # nsw-fe - sctp
iptables -A OUTPUT -p sctp --dport 27 -j DROP       # nsw-fe - sctp
iptables -A INPUT -p dccp --dport 27 -j DROP        # nsw-fe - dccp
iptables -A OUTPUT -p dccp --dport 27 -j DROP       # nsw-fe - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 28 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 28 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 28 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 28 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 28 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 28 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 28 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 28 -j DROP       # Unassigned - dccp

# MSG ICP
iptables -A INPUT -p tcp --dport 29 -j DROP         # msg-icp - tcp
iptables -A OUTPUT -p tcp --dport 29 -j DROP        # msg-icp - tcp
iptables -A INPUT -p udp --dport 29 -j DROP         # msg-icp - udp
iptables -A OUTPUT -p udp --dport 29 -j DROP        # msg-icp - udp
iptables -A INPUT -p sctp --dport 29 -j DROP        # msg-icp - sctp
iptables -A OUTPUT -p sctp --dport 29 -j DROP       # msg-icp - sctp
iptables -A INPUT -p dccp --dport 29 -j DROP        # msg-icp - dccp
iptables -A OUTPUT -p dccp --dport 29 -j DROP       # msg-icp - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 30 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 30 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 30 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 30 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 30 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 30 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 30 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 30 -j DROP       # Unassigned - dccp

# MSG Authentication
iptables -A INPUT -p tcp --dport 31 -j DROP         # msg-auth - tcp
iptables -A OUTPUT -p tcp --dport 31 -j DROP        # msg-auth - tcp
iptables -A INPUT -p udp --dport 31 -j DROP         # msg-auth - udp
iptables -A OUTPUT -p udp --dport 31 -j DROP        # msg-auth - udp
iptables -A INPUT -p sctp --dport 31 -j DROP        # msg-auth - sctp
iptables -A OUTPUT -p sctp --dport 31 -j DROP       # msg-auth - sctp
iptables -A INPUT -p dccp --dport 31 -j DROP        # msg-auth - dccp
iptables -A OUTPUT -p dccp --dport 31 -j DROP       # msg-auth - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 32 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 32 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 32 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 32 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 32 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 32 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 32 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 32 -j DROP       # Unassigned - dccp

# Display Support Protocol
iptables -A INPUT -p tcp --dport 33 -j DROP         # dsp - tcp
iptables -A OUTPUT -p tcp --dport 33 -j DROP        # dsp - tcp
iptables -A INPUT -p udp --dport 33 -j DROP         # dsp - udp
iptables -A OUTPUT -p udp --dport 33 -j DROP        # dsp - udp
iptables -A INPUT -p sctp --dport 33 -j DROP        # dsp - sctp
iptables -A OUTPUT -p sctp --dport 33 -j DROP       # dsp - sctp
iptables -A INPUT -p dccp --dport 33 -j DROP        # dsp - dccp
iptables -A OUTPUT -p dccp --dport 33 -j DROP       # dsp - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 34 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 34 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 34 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 34 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 34 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 34 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 34 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 34 -j DROP       # Unassigned - dccp

# Any private printer server
iptables -A INPUT -p tcp --dport 35 -j DROP         # any private printer server - tcp
iptables -A OUTPUT -p tcp --dport 35 -j DROP        # any private printer server - tcp
iptables -A INPUT -p udp --dport 35 -j DROP         # any private printer server - udp
iptables -A OUTPUT -p udp --dport 35 -j DROP        # any private printer server - udp
iptables -A INPUT -p sctp --dport 35 -j DROP        # any private printer server - sctp
iptables -A OUTPUT -p sctp --dport 35 -j DROP       # any private printer server - sctp
iptables -A INPUT -p dccp --dport 35 -j DROP        # any private printer server - dccp
iptables -A OUTPUT -p dccp --dport 35 -j DROP       # any private printer server - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 36 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 36 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 36 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 36 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 36 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 36 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 36 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 36 -j DROP       # Unassigned - dccp

# Time
iptables -A INPUT -p tcp --dport 37 -j DROP         # time - tcp
iptables -A OUTPUT -p tcp --dport 37 -j DROP        # time - tcp
iptables -A INPUT -p udp --dport 37 -j DROP         # time - udp
iptables -A OUTPUT -p udp --dport 37 -j DROP        # time - udp
iptables -A INPUT -p sctp --dport 37 -j DROP        # time - sctp
iptables -A OUTPUT -p sctp --dport 37 -j DROP       # time - sctp
iptables -A INPUT -p dccp --dport 37 -j DROP        # time - dccp
iptables -A OUTPUT -p dccp --dport 37 -j DROP       # time - dccp

# Route Access Protocol
iptables -A INPUT -p tcp --dport 38 -j DROP         # rap - tcp
iptables -A OUTPUT -p tcp --dport 38 -j DROP        # rap - tcp
iptables -A INPUT -p udp --dport 38 -j DROP         # rap - udp
iptables -A OUTPUT -p udp --dport 38 -j DROP        # rap - udp
iptables -A INPUT -p sctp --dport 38 -j DROP        # rap - sctp
iptables -A OUTPUT -p sctp --dport 38 -j DROP       # rap - sctp
iptables -A INPUT -p dccp --dport 38 -j DROP        # rap - dccp
iptables -A OUTPUT -p dccp --dport 38 -j DROP       # rap - dccp

# Resource Location Protocol
iptables -A INPUT -p tcp --dport 39 -j DROP         # rlp - tcp
iptables -A OUTPUT -p tcp --dport 39 -j DROP        # rlp - tcp
iptables -A INPUT -p udp --dport 39 -j DROP         # rlp - udp
iptables -A OUTPUT -p udp --dport 39 -j DROP        # rlp - udp
iptables -A INPUT -p sctp --dport 39 -j DROP        # rlp - sctp
iptables -A OUTPUT -p sctp --dport 39 -j DROP       # rlp - sctp
iptables -A INPUT -p dccp --dport 39 -j DROP        # rlp - dccp
iptables -A OUTPUT -p dccp --dport 39 -j DROP       # rlp - dccp

# Unassigned
iptables -A INPUT -p tcp --dport 40 -j DROP         # Unassigned - tcp
iptables -A OUTPUT -p tcp --dport 40 -j DROP        # Unassigned - tcp
iptables -A INPUT -p udp --dport 40 -j DROP         # Unassigned - udp
iptables -A OUTPUT -p udp --dport 40 -j DROP        # Unassigned - udp
iptables -A INPUT -p sctp --dport 40 -j DROP        # Unassigned - sctp
iptables -A OUTPUT -p sctp --dport 40 -j DROP       # Unassigned - sctp
iptables -A INPUT -p dccp --dport 40 -j DROP        # Unassigned - dccp
iptables -A OUTPUT -p dccp --dport 40 -j DROP       # Unassigned - dccp

# Graphics
iptables -A INPUT -p tcp --dport 41 -j DROP         # Graphics - tcp
iptables -A OUTPUT -p tcp --dport 41 -j DROP        # Graphics - tcp
iptables -A INPUT -p udp --dport 41 -j DROP         # Graphics - udp
iptables -A OUTPUT -p udp --dport 41 -j DROP        # Graphics - udp
iptables -A INPUT -p sctp --dport 41 -j DROP        # Graphics - sctp
iptables -A OUTPUT -p sctp --dport 41 -j DROP       # Graphics - sctp
iptables -A INPUT -p dccp --dport 41 -j DROP        # Graphics - dccp
iptables -A OUTPUT -p dccp --dport 41 -j DROP       # Graphics - dccp

# Host Name Server
iptables -A INPUT -p tcp --dport 42 -j DROP         # Nameserver - tcp
iptables -A OUTPUT -p tcp --dport 42 -j DROP        # Nameserver - tcp
iptables -A INPUT -p udp --dport 42 -j DROP         # Nameserver - udp
iptables -A OUTPUT -p udp --dport 42 -j DROP        # Nameserver - udp
iptables -A INPUT -p sctp --dport 42 -j DROP        # Nameserver - sctp
iptables -A OUTPUT -p sctp --dport 42 -j DROP       # Nameserver - sctp
iptables -A INPUT -p dccp --dport 42 -j DROP        # Nameserver - dccp
iptables -A OUTPUT -p dccp --dport 42 -j DROP       # Nameserver - dccp

# Who Is
iptables -A INPUT -p tcp --dport 43 -j DROP         # Nicname - tcp
iptables -A OUTPUT -p tcp --dport 43 -j DROP        # Nicname - tcp
iptables -A INPUT -p udp --dport 43 -j DROP         # Nicname - udp
iptables -A OUTPUT -p udp --dport 43 -j DROP        # Nicname - udp
iptables -A INPUT -p sctp --dport 43 -j DROP        # Nicname - sctp
iptables -A OUTPUT -p sctp --dport 43 -j DROP       # Nicname - sctp
iptables -A INPUT -p dccp --dport 43 -j DROP        # Nicname - dccp
iptables -A OUTPUT -p dccp --dport 43 -j DROP       # Nicname - dccp

# MPM FLAGS Protocol
iptables -A INPUT -p tcp --dport 44 -j DROP         # mpm-flags - tcp
iptables -A OUTPUT -p tcp --dport 44 -j DROP        # mpm-flags - tcp
iptables -A INPUT -p udp --dport 44 -j DROP         # mpm-flags - udp
iptables -A OUTPUT -p udp --dport 44 -j DROP        # mpm-flags - udp
iptables -A INPUT -p sctp --dport 44 -j DROP        # mpm-flags - sctp
iptables -A OUTPUT -p sctp --dport 44 -j DROP       # mpm-flags - sctp
iptables -A INPUT -p dccp --dport 44 -j DROP        # mpm-flags - dccp
iptables -A OUTPUT -p dccp --dport 44 -j DROP       # mpm-flags - dccp

# Message Processing Module [recv]
iptables -A INPUT -p tcp --dport 45 -j DROP         # mpm - tcp
iptables -A OUTPUT -p tcp --dport 45 -j DROP        # mpm - tcp
iptables -A INPUT -p udp --dport 45 -j DROP         # mpm - udp
iptables -A OUTPUT -p udp --dport 45 -j DROP        # mpm - udp
iptables -A INPUT -p sctp --dport 45 -j DROP        # mpm - sctp
iptables -A OUTPUT -p sctp --dport 45 -j DROP       # mpm - sctp
iptables -A INPUT -p dccp --dport 45 -j DROP        # mpm - dccp
iptables -A OUTPUT -p dccp --dport 45 -j DROP       # mpm - dccp

# MPM [default send]
iptables -A INPUT -p tcp --dport 46 -j DROP         # mpm-snd - tcp
iptables -A OUTPUT -p tcp --dport 46 -j DROP        # mpm-snd - tcp
iptables -A INPUT -p udp --dport 46 -j DROP         # mpm-snd - udp
iptables -A OUTPUT -p udp --dport 46 -j DROP        # mpm-snd - udp
iptables -A INPUT -p sctp --dport 46 -j DROP        # mpm-snd - sctp
iptables -A OUTPUT -p sctp --dport 46 -j DROP       # mpm-snd - sctp
iptables -A INPUT -p dccp --dport 46 -j DROP        # mpm-snd - dccp
iptables -A OUTPUT -p dccp --dport 46 -j DROP       # mpm-snd - dccp

# Reserved
iptables -A INPUT -p tcp --dport 47 -j DROP         # Reserved - tcp
iptables -A OUTPUT -p tcp --dport 47 -j DROP        # Reserved - tcp
iptables -A INPUT -p udp --dport 47 -j DROP         # Reserved - udp
iptables -A OUTPUT -p udp --dport 47 -j DROP        # Reserved - udp
iptables -A INPUT -p sctp --dport 47 -j DROP        # Reserved - sctp
iptables -A OUTPUT -p sctp --dport 47 -j DROP       # Reserved - sctp
iptables -A INPUT -p dccp --dport 47 -j DROP        # Reserved - dccp
iptables -A OUTPUT -p dccp --dport 47 -j DROP       # Reserved - dccp

# Digital Audit Daemon
iptables -A INPUT -p tcp --dport 48 -j DROP         # auditd - tcp
iptables -A OUTPUT -p tcp --dport 48 -j DROP        # auditd - tcp
iptables -A INPUT -p udp --dport 48 -j DROP         # auditd - udp
iptables -A OUTPUT -p udp --dport 48 -j DROP        # auditd - udp
iptables -A INPUT -p sctp --dport 48 -j DROP        # auditd - sctp
iptables -A OUTPUT -p sctp --dport 48 -j DROP       # auditd - sctp
iptables -A INPUT -p dccp --dport 48 -j DROP        # auditd - dccp
iptables -A OUTPUT -p dccp --dport 48 -j DROP       # auditd - dccp

# Login Host Protocol (TACACS)
iptables -A INPUT -p tcp --dport 49 -j DROP         # tacacs - tcp
iptables -A OUTPUT -p tcp --dport 49 -j DROP        # tacacs - tcp
iptables -A INPUT -p udp --dport 49 -j DROP         # tacacs - udp
iptables -A OUTPUT -p udp --dport 49 -j DROP        # tacacs - udp
iptables -A INPUT -p sctp --dport 49 -j DROP        # tacacs - sctp
iptables -A OUTPUT -p sctp --dport 49 -j DROP       # tacacs - sctp
iptables -A INPUT -p dccp --dport 49 -j DROP        # tacacs - dccp
iptables -A OUTPUT -p dccp --dport 49 -j DROP       # tacacs - dccp

# Remote Mail Checking Protocol
iptables -A INPUT -p tcp --dport 50 -j DROP         # re-mail-ck - tcp
iptables -A OUTPUT -p tcp --dport 50 -j DROP        # re-mail-ck - tcp
iptables -A INPUT -p udp --dport 50 -j DROP         # re-mail-ck - udp
iptables -A OUTPUT -p udp --dport 50 -j DROP        # re-mail-ck - udp
iptables -A INPUT -p sctp --dport 50 -j DROP        # re-mail-ck - sctp
iptables -A OUTPUT -p sctp --dport 50 -j DROP       # re-mail-ck - sctp
iptables -A INPUT -p dccp --dport 50 -j DROP        # re-mail-ck - dccp
iptables -A OUTPUT -p dccp --dport 50 -j DROP       # re-mail-ck - dccp

# Reserved
iptables -A INPUT -p tcp --dport 51 -j DROP         # Reserved - tcp
iptables -A OUTPUT -p tcp --dport 51 -j DROP        # Reserved - tcp
iptables -A INPUT -p udp --dport 51 -j DROP         # Reserved - udp
iptables -A OUTPUT -p udp --dport 51 -j DROP        # Reserved - udp
iptables -A INPUT -p sctp --dport 51 -j DROP        # Reserved - sctp
iptables -A OUTPUT -p sctp --dport 51 -j DROP       # Reserved - sctp
iptables -A INPUT -p dccp --dport 51 -j DROP        # Reserved - dccp
iptables -A OUTPUT -p dccp --dport 51 -j DROP       # Reserved - dccp

# HTTP
iptables -A INPUT -p tcp --dport 80 -j DROP         # HTTP - tcp
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT      # HTTP - tcp
iptables -A INPUT -p udp --dport 80 -j DROP         # HTTP - udp
iptables -A OUTPUT -p udp --dport 80 -j DROP        # HTTP - udp
iptables -A INPUT -p sctp --dport 80 -j DROP        # HTTP - sctp
iptables -A OUTPUT -p sctp --dport 80 -j DROP       # HTTP - sctp
iptables -A INPUT -p dccp --dport 80 -j DROP        # HTTP - dccp
iptables -A OUTPUT -p dccp --dport 80 -j DROP       # HTTP - dccp

# HTTPS
iptables -A INPUT -p tcp --dport 443 -j DROP        # HTTPS - tcp
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT     # HTTPS - tcp
iptables -A INPUT -p udp --dport 443 -j DROP        # HTTPS - udp
iptables -A OUTPUT -p udp --dport 443 -j DROP       # HTTPS - udp
iptables -A INPUT -p sctp --dport 443 -j DROP       # HTTPS - sctp
iptables -A OUTPUT -p sctp --dport 443 -j DROP      # HTTPS - sctp
iptables -A INPUT -p dccp --dport 443 -j DROP       # HTTPS - dccp
iptables -A OUTPUT -p dccp --dport 443 -j DROP      # HTTPS - dccp
