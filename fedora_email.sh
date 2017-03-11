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
iptables -A INPUT ! -s 172.20.240.0/22 -m recent --update --seconds 10 --hitcount 20 -j REDTEAM

# Allow email traffic
iptables -A INPUT -p tcp --dport 25 -m state --state new -j ACCEPT
iptables -A INPUT -p tcp --dport 110 -m state --state new -j ACCEPT
iptables -A INPUT -p tcp --dport 143 -m state --state new -j ACCEPT
iptables -A INPUT -p tcp --dport 995 -m state --state new -j ACCEPT

# Allow http traffic
iptables -A INPUT -p tcp --dport 80 -m state --state new -j ACCEPT

# Allow https traffic
iptables -A INPUT -p tcp --dport 443 -m state --state new -j ACCEPT

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

# Allow mysql traffic (roundcube)
iptables -A OUTPUT -p tcp --dport 3306 -d 172.20.240.20 -m state --state new -j ACCEPT

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
iptables-save
#iptables-save > /etc/iptables
#echo '#!/bin/sh' > /etc/network/if-pre-up.d/iptables
#echo 'iptables-restore < /etc/iptables' >> /etc/network/if-pre-up.d/iptables
#chmod +x /etc/network/if-pre-up.d/iptables

# Stop services (Covered by iptables script)
service atd stop
service crond stop
service nfs-common stop
service sshd stop
service portmap stop
service postfix stop
service avahi-daemon stop
service anacron stop

# Remove services (Covered by iptables script)
chkconfig atd off
chkconfig crond off
chkconfig nfs-common off
chkconfig sshd off
chkconfig portmap off
chkconfig postfix off
chkconfig avahi-daemon off
chkconfig anacron off

# System cleanup
crontab -u root -r
crontab -u administrator -r
crontab -u mailserver -r
rm -f /etc/localtime
ln -s /usr/share/zoneinfo/America/Chicago /etc/localtime

# setup pam tally
#cp /etc/pam.d/common-auth /etc/common-auth.bak
#echo 'auth required pam_tally.so onerr=fail deny=3 even_deny_root unlock_time=300' > /etc/pam.d/common_auth
#echo 'auth sufficient pam_unix.so nullok_secure' >> /etc/pam.d/common_auth
#echo 'auth sufficient winbind.so' >> /etc/pam.d/common_auth
#cp /etc/pam.d/common-account /etc/common-account.bak
#echo 'account required pam_tally.so per_user' > /etc/pam.d/common_account
#echo 'account sufficient pam_unix.so'  >> /etc/pam.d/common_account
#echo 'account sufficient winbind.so' >> /etc/pam.d/common_account
#sed -i 's/obscure md5/obscure sha512/' /etc/pam.d/common-password
#chmod 0000 /etc/shadow

# Secure Apache2 (Prevent XXS)
echo 'ServerName mail.team.local' > /etc/httpd/conf.d/01_httpd.conf
echo 'RewriteEngine on' >> /etc/httpd/conf.d/01_httpd.conf
echo 'RewriteCond %{REQUEST_METHOD} ^{TRACE|TRACK}' >> /etc/httpd/conf.d/01_httpd.conf
echo 'RewriteRule .* - [F]' >> /etc/httpd/conf.d/01_httpd.conf
echo 'Header edit Set-Cookie ^(.*)$ $1;HttpOnly' >> /etc/httpd/conf.d/01_httpd.conf
echo 'TraceEnable off' >> /etc/httpd/conf.d/01_httpd.conf
/etc/init.d/httpd restart
rm -rf /var/www/phpchat

# Secure Dovecot (Add TLS)
cp /etc/dovecot/dovecot.conf /etc/dovecot/dovecot.conf.old
sed -i 's/#ssl_disable/ssl_disable/' /etc/dovecot/dovecot.conf
sed -i 's/#ssl_cipher_list.*/ssl_cipher_list = ALL:!LOW:!SSLv2:!EXP:!aNULL/' /etc/dovecot/dovecot.conf
sed -i 's/protocols =.*/protocols = imap pop3 imaps pop3s/' /etc/dovecot/dovecot.conf
/etc/init.d/dovecot restart

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
