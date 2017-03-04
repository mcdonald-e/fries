#!/bin/sh

# Clear all exsisting rules
iptables -F

# Set default action to drop packets
iptables -P FORWARD DROP
iptables -P OUTPUT DROP
iptables -P INPUT DROP

# Create table for blacklist
iptables -N REDTEAM
iptables -A REDTEAM -m recent --remove
iptables -A REDTEAM -m recent --name redteam --set
iptables -A REDTEAM -j LOG --log-prefix "Redteam Blocked: "

#####SETUP INBOUND RULE ######
# Allow local traffic
iptables -A INPUT -i lo -j ACCEPT

# Prevent SYN packet attacks
iptables -A INPUT -p tcp ! --syn -m state --state NEW -m limit --limit 1/min -j LOG --log-prefix "SYN packet flood: "
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Prevent fragmented packets
iptables -A INPUT -f -m limit --limit 1/min -j LOG --log-prefix "Fragmented packet: "
iptables -A INPUT -f -j DROP

# Prevent XMAS attacks
iptables -A INPUT -p tcp --tcp-flags ALL ALL -m limit --limit 1/min -j LOG --log-prefix "XMAS packet: "
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Prevent NULL attacks
iptables -A INPUT -p tcp --tcp-flags ALL NONE -m limit --limit 1/min -j LOG --log-prefix "NULL packet: "
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Allow ping with limits
iptables -A INPUT -p icmp -m limit --limit 3/sec -j ACCEPT

# Drop packets from blacklisted ip for 10 minutes
iptables -A INPUT -m recent --rcheck --name redteam --seconds 600 -j DROP

# Flag excessive pings as flood attack
iptables -A INPUT -p icmp -m limit --limit 1/minute -j LOG --log-prefix "ICMP Flood: "

# Allow all traffic already established
iptables -A INPUT -m state --state established,related -j ACCEPT

# Remember all ip connections and send excessive requests to blacklist
iptables -A INPUT -m state --state NEW -m recent --set
iptables -A INPUT ! -s 172.20.240.0/23 -m recent --update --seconds 10 --hitcount 20 -j REDTEAM

# Allow mysql traffic
iptables -A INPUT -p tcp --dport 3306 -s 172.20.241.40 -m state --state new -j ACCEPT

# Allow ssh traffic
iptables -A INPUT -p tcp --dport 22 -s 172.20.240.0/22 -m state --state new -j ACCEPT

# Allow samba traffic (optional)
#iptables -A INPUT -p tcp --dport 445 -m state --state new -j ACCEPT
#iptables -A INPUT -p tcp --dport 137 -m state --state new -j ACCEPT
#iptables -A INPUT -p tcp --dport 138 -m state --state new -j ACCEPT
#iptables -A INPUT -p tcp --dport 139 -m state --state new -j ACCEPT

#####SETUP OUTBOUND RULES #####
# Allow local traffic
iptables -A OUTPUT -o lo -j ACCEPT

# Allow all traffic already established
iptables -A OUTPUT -m state --state established,related -j ACCEPT

# Allow http traffic
iptables -A OUTPUT -p tcp --dport 80 -m state --state new -j ACCEPT

# Allow ldap traffic
iptables -A OUTPUT -p tcp --dport 389 -d 172.20.242.200 -m state --state new -j ACCEPT
iptables -A OUTPUT -p tcp --dport 636 -d 172.20.242.200 -m state --state new -j ACCEPT
iptables -A OUTPUT -p udp --dport 389 -d 172.20.242.200 -m state --state new -j ACCEPT
iptables -A OUTPUT -p udp --dport 636 -d 172.20.242.200 -m state --state new -j ACCEPT

# Allow https traffic
iptables -A OUTPUT -p tcp --dport 443 -m state --state new -j ACCEPT

# Allow ssh traffic
iptables -A OUTPUT -p tcp --dport 22 -d 172.20.240.0/22 -m state --state new -j ACCEPT

# Allow dns traffic
iptables -A OUTPUT -p udp --dport 53 -m state --state new -j ACCEPT

# Allow ntp traffic
iptables -A OUTPUT -p udp --dport 123 -d 172.20.240.0/22 -m state --state new -j ACCEPT

# Allow rsyslog traffic to send logs
iptables -A OUTPUT -p udp --dport 514 -d 172.20.240.0/22 -m state --state new -j ACCEPT

# Allow ping
iptables -A OUTPUT -p icmp -m limit --limit 2/sec -j ACCEPT

# Log everything else about to be dropped
iptables -A OUTPUT -m limit --limit 2/min -j LOG --log-prefix "Output-Dropped: " --log-level 4
iptables -A INPUT -m limit --limit 2/min -j LOG --log-prefix "Input-Dropped: " --log-level 4
iptables -A FORWARD -m limit --limit 2/min -j LOG --log-prefix "Forward-Dropped: " --log-level 4

# Save the filter rules
iptables-save > /etc/iptables
echo '#!/bin/sh' > /etc/network/if-pre-up.d/iptables
echo 'iptables-restore < /etc/iptables' >> /etc/network/if-pre-up.d/iptables
chmod +x /etc/network/if-pre-up.d/iptables

# Stop services (Covered by iptables script)
/etc/init.d/atd stop
/etc/init.d/cron stop
/etc/init.d/nfs-common stop
/etc/init.d/ssh stop
/etc/init.d/portmap stop
/etc/init.d/postfix stop
/etc/init.d/avahi-daemon stop
/etc/init.d/anacron stop

# Remove services (Covered by iptables script)
update-rc.d -f atd remove
update-rc.d -f cron remove
update-rc.d -f nfs-common remove
update-rc.d -f ssh remove
update-rc.d -f portmap remove
update-rc.d -f postfix remove
update-rc.d -f avahi-daemon remove
update-rc.d -f anacron remove

# Remove iSCSI from network config
mv /etc/network/if-up.d/mountnfs /etc/network
mv /etc/network/if-up.d/avahi-daemon /etc/network
mv /etc/network/if-up.d/postfix /etc/network

# System cleanup
#sed -i 's_/dev/hdc_#/dev/hdc_' /etc/fstab
crontab -u root -r
crontab -u administrator -r
rm -f /etc/localtime
ln -s /usr/share/zoneinfo/America/Chicago /etc/localtime

# update apt-get repos
cp /etc/apt/sources.list /etc/apt/sources.list.bak
echo 'deb http://ftp.debian.org/debian/ wheezy main contrib non-free' >> /etc/apt/sources.list
echo 'deb-src http://ftp.debian.org/debian/ wheezy main contrib non-free' >> /etc/apt/sources.list
echo 'deb http://ftp.debian.org/debian/ wheezy-updates main contrib non-free' >> /etc/apt/sources.list
echo 'deb-src http://ftp.debian.org/debian/ wheezy-updates main contrib non-free' >> /etc/apt/sources.list
#echo 'deb http://ftp.debian.org/debian/ Debian7.11 main contrib non-free' >> /etc/apt/sources.list
#echo 'deb-src http://ftp.debian.org/debian/ Debian7.11 main contrib non-free' >> /etc/apt/sources.list

# setup pam tally
cp /etc/pam.d/common-auth /etc/common-auth.bak
echo 'auth required pam_tally.so onerr=fail deny=3 even_deny_root unlock_time=300' > /etc/pam.d/common_auth
echo 'auth sufficient pam_unix.so nullok_secure' >> /etc/pam.d/common_auth
#echo 'auth sufficient winbind.so' >> /etc/pam.d/common_auth
cp /etc/pam.d/common-account /etc/common-account.bak
echo 'account required pam_tally.so per_user' > /etc/pam.d/common_account
echo 'account sufficient pam_unix.so'  >> /etc/pam.d/common_account
#echo 'account sufficient winbind.so' >> /etc/pam.d/common_account
sed -i 's/obscure md5/obscure sha512/' /etc/pam.d/common-password
chmod 0000 /etc/shadow

# NTP setup
echo -e '\nserver 172.20.240.254 prefer' >> /etc/ntp.conf

# Setup central logging
echo -e '\n*.* @172.20.241.27:514' >> /etc/rsyslog.conf
/etc/init.d/rsyslog restart

# Gereate new ssh keys
sed -i 's/#PermitRoot.*/PermitRootLogin no/' /etc/ssh/sshd_config
echo -e '\nCiphers aes256-ctr' >> /etc/ssh/sshd_config
echo 'MACs hmac-sha1' >> /etc/ssh/sshd_config
echo -e '\n\nGenerating new ssh keys\nEnter y to overwrite and enter for passwords\n'
cd /etc/ssh
ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key
ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key
ssh-keygen -t rsa1 -f /etc/ssh/ssh_host_key

# Take process snapshot
cd /etc/bin
ps -A | cut -d ':' -f3 | cut -d ' ' -f2 | sort -k2 > snapshot
