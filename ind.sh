#!/bin/bash
# go to root
cd
echo -e "\e[32;32;32m " 
echo "================================================================="
echo "|| Welcome To Script Automatic Install Army Phreakers Nusantara ||"
echo "|| Script Modified By Reza Adrian | Whatsapp: 081214422324      ||"
echo "================================================================"

url="google.com"
myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;

flag=0

echo

if [ $USER != 'root' ]; then
	echo "Sorry, for run the script please using root user"
	exit
fi
wget -q -O IP https://ipublic.me/ipku.txt
if ! grep -w -q $myip IP; then
	echo "Maaf, hanya IP yang terdaftar yang bisa menggunakan script ini!"
	echo "Jika Berminat menggunakan Auto Script Premium ini silahkan hubungi admin :)"
	rm /root/IP
	rm ind.sh
	rm -f /root/IP
	exit
fi
apt-get update

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
#MYIP=$(wget -qO- ipv4.icanhazip.com);

echo "Proses instalasi script dimulai....."

MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# go to root
cd
echo "=============================="
echo "        Setup Awal        "
echo "=============================="
echo -e "\e[32;32;32m"    
# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local
#sed -i 's/net.ipv6.conf.all.disable_ipv6 = 0/net.ipv6.conf.all.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.default.disable_ipv6 = 0/net.ipv6.conf.default.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.lo.disable_ipv6 = 0/net.ipv6.conf.lo.disable_ipv6 = 1/g' /etc/sysctl.conf
#sed -i 's/net.ipv6.conf.eth0.disable_ipv6 = 0/net.ipv6.conf.eth0.disable_ipv6 = 1/g' /etc/sysctl.conf
#sysctl -p
echo -e "\e[32;32;32m " 
echo "=============================="
echo "     INSTALL CURL     "
echo "=============================="
# install wget and curl
apt-get update;apt-get -y install wget curl;
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart
# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y --purge remove dropbear*;
#apt-get -y autoremove;
echo -e "\e[32;32;32m " 
echo "=============================="
echo "       REPOSITORI "
echo "=============================="
# set repo
cat > /etc/apt/sources.list <<END2
deb http://security.debian.org/ jessie/updates main contrib non-free
deb-src http://security.debian.org/ jessie/updates main contrib non-free
deb http://http.us.debian.org/debian jessie main contrib non-free
deb http://packages.dotdeb.org jessie all
deb-src http://packages.dotdeb.org jessie all
END2
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
# update
apt-get update;apt-get -y upgrade;

# install webserver
apt-get -y install nginx php5-fpm php5-cli

# install screenfetch
cd
wget https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/screenfetch.sh
mv screenfetch.sh /usr/bin/screenfetch
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch | lolcat && welcomeadmin" >> .profile

# install essential package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
apt-get -y install bmon 
apt-get -y install iftop 
apt-get -y install htop 
apt-get -y install nmap 
apt-get -y install axel 
apt-get -y install nano 
apt-get -y install iptables 
apt-get -y install traceroute 
apt-get -y install sysv-rc-conf 
apt-get -y install dnsutils 
apt-get -y install nethogs
apt-get -y install vnstat 
apt-get -y install less 
apt-get -y install apt-file 
apt-get -y install whois  
apt-get -y install ngrep 
apt-get -y install mtr 
apt-get -y install git
apt-get -y install zsh 
apt-get -y install wget screen
apt-get -y install mrtg 
apt-get -y install snmp 
apt-get -y install unzip 
apt-get -y install unrar 
apt-get -y install rsyslog 
apt-get -y install debsums 
apt-get -y install rkhunter
apt-get -y install build-essential
apt-get -y --force-yes -f install libxml-parser-perl

echo -e "\e[32;32;32m"  
echo "=============================="
echo "  UPDATE ALL SERVICE        "
echo "=============================="

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i $ether
service vnstat restart

    NORMAL=`echo "\033[m"`
    MENU=`echo "\033[36m"` #Blue
    NUMBER=`echo "\033[33m"` #yellow
    FGRED=`echo "\033[41m"`
    RED_TEXT=`echo "\033[31m"`
	LGREEN=`echo "\033[0m\033[1;32m"`
    ENTER_LINE=`echo "\033[33m"`
	LRED=`echo "\033[0m\033[1;31m"`
	BLUE=`echo "\033[0m\033[1;36m"`

# go to root
cd

# install gambar boxes
apt-get -y install boxes

# text warna pelangi
sudo apt-get -y install ruby
sudo gem install lolcat 

# tampilan unik awal login
#cd
#rm -rf /root/.bashrc
#wget -O /root/.bashrc "https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/welcome.sh"

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/nginx.conf"
mkdir -p /home/vps/public_html
echo "<pre>Setup by Army Phreakers Nusantara</pre>" > /home/vps/public_html/index.html
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/rizal180499/Auto-Installer-VPS/master/conf/vps.conf"
sed -i 's/listen = \/var\/run\/php5-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php5/fpm/pool.d/www.conf
service php5-fpm restart
service nginx restart

# install mrtg
wget -O /etc/snmp/snmpd.conf "https://raw.github.com/arieonline/autoscript/master/conf/snmpd.conf"
wget -O /root/mrtg-mem.sh "https://raw.github.com/arieonline/autoscript/master/conf/mrtg-mem.sh"
chmod +x /root/mrtg-mem.sh
cd /etc/snmp/
sed -i 's/TRAPDRUN=no/TRAPDRUN=yes/g' /etc/default/snmpd
service snmpd restart
snmpwalk -v 1 -c public localhost 1.3.6.1.4.1.2021.10.1.3.1
mkdir -p /home/vps/public_html/mrtg
cfgmaker --zero-speed 100000000 --global 'WorkDir: /home/vps/public_html/mrtg' --output /etc/mrtg.cfg public@localhost
curl "https://raw.github.com/arieonline/autoscript/master/conf/mrtg.conf" >> /etc/mrtg.cfg
sed -i 's/WorkDir: \/var\/www\/mrtg/# WorkDir: \/var\/www\/mrtg/g' /etc/mrtg.cfg
sed -i 's/# Options\[_\]: growright, bits/Options\[_\]: growright/g' /etc/mrtg.cfg
indexmaker --output=/home/vps/public_html/mrtg/index.html /etc/mrtg.cfg
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
if [ -x /usr/bin/mrtg ] && [ -r /etc/mrtg.cfg ]; then mkdir -p /var/log/mrtg ; env LANG=C /usr/bin/mrtg /etc/mrtg.cfg 2>&1 | tee -a /var/log/mrtg/mrtg.log ; fi
cd

# setting port ssh
cd
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22/a Port 143' /etc/ssh/sshd_config
service ssh restart

# configure ssh
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i '/Port 22' /etc/ssh/sshd_config

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=80/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 444 -p 442"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
service ssh restart
service dropbear restart

# upgrade dropbear 2018
apt-get install zlib1g-dev
wget -q https://matt.ucc.asn.au/dropbear/releases/dropbear-2018.76.tar.bz2
bzip2 -cd dropbear-2018.76.tar.bz2 | tar xvf -
cd dropbear-2018.76
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear1
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
service dropbear restart

# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://github.com/ForNesiaFreak/FNS/raw/master/sett/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
wget -O /usr/bin/badvpn-udpgw "https://github.com/ForNesiaFreak/FNS/raw/master/sett/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200

# Install VNSTAT
wget https://humdi.net/vnstat/vnstat-latest.tar.gz
tar zxvf vnstat-latest.tar.gz
cd vnstat-*

echo -e "\e[32;32;32m"
echo "=============================="
echo "        INSTALL BADVPN       "
echo "=============================="

# nstall fail2ban
apt-get -y install fail2ban;service fail2ban restart

# Instal (D)DoS Deflate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# install webmin
cd
wget -O webmin-current.deb http://www.webmin.com/download/deb/webmin-current.deb
dpkg -i --force-all webmin-current.deb
apt-get -y -f install;
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm -f /root/webmin-current.deb
service webmin restart
service vnstat restart

# Banner ssh 
wget -O /etc/issue.net "https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/issue.net"
sed -i 's@#Banner@Banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
service ssh restart
service dropbear restart

# install dos2unix
apt-get install dos2unix

wget -q https://github.com/ForNesiaFreak/FNS/raw/master/go/fornesia87.tgz
tar xvfz fornesia87.tgz
cd fornesia87
make

# install stunnel
apt-get -y install stunnel4
cat > /etc/stunnel/stunnel.conf <<-END  
cert = /etc/stunnel/stunnel.pem
pid = /stunnel.pid
client = no	
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
accept = 443
connect = 127.0.0.1:442
END
#membuat sertifikat
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

#konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4

# install squid3
apt-get -y install squid3
cat > /etc/squid3/squid.conf <<-END
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx-xxxxxxxxx/32
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8080
http_port 3128
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname Proxy.apn.net
END
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

#ADD MENU + Compiler
wget -q https://raw.githubusercontent.com/Mr-Kenyut/VPS/master/menu.sh
dos2unix /root/fornesia87/menu.sh


# download script lain + Compile
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/trial.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-add.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-generate.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/expiry-change.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-del.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-login.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/dropmon.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw//master/user-limit.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/autokill.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-list.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-delete-pptp.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-detail-pptp.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-expired.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/del-user-expire.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-ban.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-unban.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-add-pptp.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/user-login-pptp.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/all-user-pptp.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/banner.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/bench-network.sh
wget -q https://github.com/Mr-Kenyut/VPS/raw/master/auto-reboot.sh


cp /root/fornesia87/user-generate.sh /usr/bin/user-generate
cp /root/fornesia87/trial.sh /usr/bin/trial
cp /root/fornesia87/expiry-change.sh /usr/bin/expiry-change
cp /root/fornesia87/user-del.sh /usr/bin/user-del
cp /root/fornesia87/user-login.sh /usr/bin/user-login
cp /root/fornesia87/menu.sh /usr/bin/menu
cp /root/fornesia87/user-add.sh /usr/bin/user-add
cp /root/fornesia87/dropmon.sh /usr/bin/dropmon
cp /root/fornesia87/user-limit.sh /usr/bin/user-limit
cp /root/fornesia87/autokill.sh /usr/bin/autokill
cp /root/fornesia87/user-list.sh /usr/bin/user-list
cp /root/fornesia87/user-expired.sh /usr/bin/user-expired
cp /root/fornesia87/del-user-expire.sh /usr/bin/del-user-expire
cp /root/fornesia87/user-add-pptp.sh /usr/bin/user-add-pptp
cp /root/fornesia87/user-unban.sh /usr/bin/user-unban
cp /root/fornesia87/user-login-pptp.sh /usr/bin/user-login-pptp
cp /root/fornesia87/all-user-pptp.sh /usr/bin/all-user-pptp
cp /root/fornesia87/user-delete-pptp.sh /usr/bin/user-delete-pptp
cp /root/fornesia87/user-detail-pptp.sh /usr/bin/user-detail-pptp
cp /root/fornesia87/banner.sh /usr/bin/banner
cp /root/fornesia87/user-ban.sh /usr/bin/user-ban
cp /root/fornesia87/bench-network.sh /usr/bin/bench-network
cp /root/fornesia87/user-unban.sh /usr/bin/user-unban
cp /root/fornesia87/auto-reboot.sh /usr/bin/auto-reboot

# Download Lain
cd
wget -q -O /usr/bin/welcomeadmin https://github.com/Mr-Kenyut/VPS/raw/master/welcome.sh
wget -q -O /usr/bin/speedtest https://github.com/Mr-Kenyut/VPS/raw/master/speedtest.py

chmod +x /usr/bin/welcomeadmin
chmod +x /usr/bin/speedtest
chmod +x /usr/bin/user-add-pptp
chmod +x /usr/bin/menu
chmod +x /usr/bin/user-add
chmod +x /usr/bin/user-generate
chmod +x /usr/bin/trial
chmod +x /usr/bin/expiry-change
chmod +x /usr/bin/user-del
chmod +x /usr/bin/user-login
chmod +x /usr/bin/dropmon
chmod +x /usr/bin/user-limit
chmod +x /usr/bin/autokill
chmod +x /usr/bin/user-login-pptp
chmod +x /usr/bin/all-user-pptp
chmod +x /usr/bin/user-list
chmod +x /usr/bin/user-expired
chmod +x /usr/bin/del-user-expire
chmod +x /usr/bin/user-ban
chmod +x /usr/bin/user-delete-pptp
chmod +x /usr/bin/user-add-pptp
chmod +x /usr/bin/user-detail-pptp
chmod +x /usr/bin/banner
chmod +x /usr/bin/auto-reboot

# blokir Torrent
iptables -A OUTPUT -p tcp --dport 6881:6889 -j DROP
iptables -A OUTPUT -pS udp --dport 1024:65534 -j DROP
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

# blokir sony playstation
iptables -A FORWARD -m string --algo bm --string "account.sonyentertainmentnetwork.com" -j DROP
iptables -A FORWARD -m string --algo bm --string "auth.np.ac.playstation.net" -j DROP
iptables -A FORWARD -m string --algo bm --string "auth.api.sonyentertainmentnetwork.com" -j DROP
iptables -A FORWARD -m string --algo bm --string "auth.api.np.ac.playstation.net" -j DROP

# finishing
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
service webmin restart
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# info
clear
echo -e "${LRED}Autoscript Includes:${NORMAL}" | tee log-install.txt
echo ""  | tee -a log-install.txt
echo -e "Silakan Ketik ${NORMAL}menu ${NORMAL}Untuk Akses Fitur"  | tee -a log-install.txt
echo -e "${LRED}Fitur lain${NORMAL}"  | tee -a log-install.txt
echo "----------"  | tee -a log-install.txt
echo -e "${LGREEN}Webmin   : ${NORMAL}http://$MYIP:10000/"  | tee -a log-install.txt
echo -e "${LGREEN}Timezone : ${NORMAL}Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo -e "${LGREEN}Fail2Ban : ${NORMAL}[on]"  | tee -a log-install.txt
echo -e "${LGREEN}(D)DoS Deflate : ${NORMAL}[on]" | tee -a log-install.txt
echo -e "${LGREEN}IPv6     : ${NORMAL}[off]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Log Installasi --> /root/log-install.txt"  | tee -a log-install.txt
echo "SILAHKAN REBOOT VPS ANDA !"  | tee -a log-install.txt

cd
rm -f /root/ind.sh
rm -f /root/addpptp.sh
rm -f /root/menu.sh
rm -r /root/fornesia87
rm -r /root/fornesia87.tgz
rm -f /root/speedtest_cli.py
rm -f /root/ps_mem.py
rm -f /root/screenfetch.sh
rm -f /root/daftarip
rm -f /root/webmin_1.831_all.deb
rm -f /root/dropbear-2018.76.tar.bz2
rm -rf /root/dropbear-2018.76
