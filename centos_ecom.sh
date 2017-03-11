#$/bin/sh

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

# Allow http traffic
iptables -A INPUT -p tcp --dport 80 -m state --state new -j ACCEPT

# Allow https traffic
iptables -A INPUT -p tcp --dport 443 -m state --state new -j ACCEPT

# Allow tomcat traffic (only needed if using ehour)
iptables -A INPUT -p tcp --dport 8080 -m state --state new -j ACCEPT

#####SETUP OUTBOUND RULES #####
# Allow local traffic
iptables -A OUTPUT -o lo -j ACCEPT

# Allow all traffic already established
iptables -A OUTPUT -m state --state established,related -j ACCEPT

# Allow http traffic
iptables -A OUTPUT -p tcp --dport 80 -m state --state new -j ACCEPT

# Allow ldap traffic
iptables -A OUTPUT -p tcp --dport 389 -d 172.20.242.1/24 -m state --state new -j ACCEPT
iptables -A OUTPUT -p tcp --dport 636 -d 172.20.242.1/24 -m state --state new -j ACCEPT
iptables -A OUTPUT -p udp --dport 389 -d 172.20.242.1/24 -m state --state new -j ACCEPT
iptables -A OUTPUT -p udp --dport 636 -d 172.20.242.1/24 -m state --state new -j ACCEPT

# Allow https traffic
iptables -A OUTPUT -p tcp --dport 443 -m state --state new -j ACCEPT

# Allow mysql traffic
iptables -A OUTPUT -p tcp --dport 3306 -d 172.20.240.20 -m state --state new -j ACCEPT

# Allow ssh traffic
iptables -A OUTPUT -p tcp --dport 22 -d 172.20.240.1/22 -m state --state new -j ACCEPT

# Allow mail traffic
iptables -A OUTPUT -p tcp -m multiports --dports 25,110,143,995 -d 172.20.240.1/22 -m state --state new -j ACCEPT

# Allow dns traffic
iptables -A OUTPUT -p udp --dport 53 -m state --state new -j ACCEPT

# Allow ntp traffic
iptables -A OUTPUT -p udp --dport 123 -d 172.20.240.1/22 -m state --state new -j ACCEPT

# Allow rsyslog traffic to send logs
iptables -A OUTPUT -p udp --dport 514 -d 172.20.240.1/22 -m state --state new -j ACCEPT

# Allow ping
iptables -A OUTPUT -p icmp -m limit --limit 2/sec -j ACCEPT

# Log everything else about to be dropped
iptables -A OUTPUT -m limit --limit 2/min -j LOG --log-prefix "Output-Dropped: " --log-level 4
iptables -A INPUT -m limit --limit 2/min -j LOG --log-prefix "Input-Dropped: " --log-level 4
iptables -A FORWARD -m limit --limit 2/min -j LOG --log-prefix "Forward-Dropped: " --log-level 4

# Save the filter rules
service iptables save

# Disable LDAP
authconfig --disableldapauth --disableldap --enableshadow --passalgo=sha512  --updateall
chmod 0000 /etc/shadow

# Stop services
service proftpd stop
service bluetooth stop
service cups stop
service crond stop
service atd stop
service lisa stop
service iscsi stop
service iscsid stop
service anacron stop
service autofs stop
service hidd stop
service kudzu stop
service pcscd stop
service xfs stop
service vncserver stop
service mysqld stop
service haldaemon stop
service messagebus stop
service dropbox stop
service oddjobd stop
service sshd stop
service portmap stop
service tomcat5 stop
service rpcidmapd stop
service hplip stop
service nfslock stop

# Remove service startup
chkconfig proftpd off
chkconfig bluetooth off
chkconfig cups off
chkconfig crond off
chkconfig atd off
chkconfig lisa off
chkconfig iscsi off
chkconfig iscsid off
chkconfig anacron off
chkconfig autofs off
chkconfig hidd off
chkconfig kudzu off
chkconfig pcscd off
chkconfig xfs off
chkconfig vncserver off
chkconfig mysqld off
chkconfig haldaemon off
chkconfig messagebus off
chkconfig dropbox off
chkconfig oddjobd off
chkconfig sshd off
chkconfig portmap off
chkconfig tomcat5 off
chkconfig rpcidmapd off
chkconfig hplip off
chkconfig nfslock off

# Fix backend link in Virtuemart
#sed -i 's/172.25.[0-9]*.[0-9]*/172.20.241.30/' /home/administrator/joomla/administrator/components/com_virtuemart/virtuemart.cfg.php
#sed -i "s/var \$ftp_enable.*/var \$ftp_enable = \'0\'\;/" /var/www/html/configuration.php
#sed -i "s/var \$user.*/var \$user = \'virt\'\;/" /var/www/html/configuration.php
#sed -i "s/var \$host.*/var \$host = \'172.20.240.20\'\;/" /var/www/html/configuration.php
#sed -i "s/var \$password.*/var \$password = \'change\'\;/" /var/www/html/configuration.php

# Remove extra tomcat apps
rm -rf /usr/share/tomcat5/webapps/jsp-examples/
rm -rf /usr/share/tomcat5/webapps/sample/
rm -rf /usr/share/tomcat5/webapps/servlets-examples/
rm -rf /usr/share/tomcat5/webapps/webdav/
rm -rf /usr/share/tomcat5/webapps/tomcat-docs/
rm -rf /usr/share/tomcat5/webapps/balancer/

# update Tomcat user
#cp /usr/share/tomcat5/conf/tomcat-users.xml /usr/share/tomcat5/conf/tomcat-users.xml.old
#echo "<?xml version='1.0' encoding='utf-8'?>" > /usr/share/tomcat5/conf/tomcat-users.xml
#echo "<tomcat-users>" >> /usr/share/tomcat5/conf/tomcat-users.xml
#echo '  <role rolename="manager"/>' >> /usr/share/tomcat5/conf/tomcat-users.xml
#echo '  <user username="admin" password="change" roles="manager"/>' >> /usr/share/tomcat5/conf/tomcat-users.xml
#echo '</tomcat-users>' >> /usr/share/tomcat5/conf/tomcat-users.xml

# Set localtime zone
rm /etc/localtime
ln -s /usr/share/zoneinfo/America/Chicago /etc/localtime

# Setup ssh
sed -i 's/#PermitRoot.*/PermitRootLogin no/' /etc/ssh/sshd_config
echo 'Ciphers aes256-ctr' >> /etc/ssh/sshd_config
echo 'MACs hmac-sha1' >> /etc/ssh/sshd_config

# Fix ehour
#sed -i 's/username=.*/username="ehour"/' /usr/share/tomcat5/conf/Catalina/localhost/ehour.xml
#sed -i 's/password=.*/password="change"/' /usr/share/tomcat5/conf/Catalina/localhost/ehour.xml

# Fix Apache2
echo 'RewriteEngine on' > /etc/httpd/conf.d/00_xxs.conf
echo 'RewriteCond %{REQUEST_METHOD} ^{TRACE|TRACK}' >> /etc/httpd/conf.d/00_xxs.conf
echo 'RewriteRule .* - [F]' >> /etc/httpd/conf.d/00_xxs.conf
echo 'Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure' >> /etc/httpd/conf.d/00_xxs.conf
echo 'TraceEnable off' >> /etc/httpd/conf.d/00_xxs.conf
echo 'Header always append X-Frame-Options SAMEORIGIN' >> /etc/httpd/conf.d/00_xxs.conf
echo 'Header set X-XSS-Protection "1; mode=block"' >> /etc/httpd/conf.d/00_xxs.conf
echo 'Header set X-Content-Type-Options nosniff' >> /etc/httpd/conf.d/00_xxs.conf
echo 'ServerSignature Off' >> /etc/httpd/conf.d/00_xxs.conf
echo 'ServerTokens Prod' >> /etc/httpd/conf.d/00_xxs.conf
echo 'Options -Indexes' >> /var/www/html/.htaccess
rm -f /var/www/html/robots.txt
rm -rf /var/www/manual
sed -i 's/SSLProtocol.*/SSLProtocol all -SSLv2 -SSLv3/' /etc/httpd/conf.d/ssl.conf
sed -i 's/SSLCipher.*/SSLCipherSuite ALL:!LOW:!MED:!SSLv2:!EXP:!aNULL/' /etc/httpd/conf.d/ssl.conf

echo -e "\n\nGenerate http certs"
cd /etc/pki/tls/private
openssl req -newkey rsa:2048 -nodes -keyout localhost.key -x509 -out localhost.crt
mv localhost.crt ../certs/

echo -e "\n\nGererate ssh keys"
cd /etc/ssh
ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key
ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key
ssh-keygen -t rsa1 -f /etc/ssh/ssh_host_key

# Force TLS only
#sed -i 's/RewriteEngine.*/RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule \(.\*\) https:\/\/%{HTTP_HOST}%{REQUEST_URI}/' /var/www/html/.htaccess
#echo 'RewriteCond %{HTTPS} off' >> /var/www/html/.htaccess
#echo 'RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}' >> /var/www/html/.htaccess
#sed -i "s/var \$force_ssl.*/var \$force_ssl = \'1\';/" /var/www/html/configuration.php
service httpd restart

# take process snapshot
ps -A | cut -d ':' -f3 | cut -d ' ' -f2 | sort -k2 > snapshot

