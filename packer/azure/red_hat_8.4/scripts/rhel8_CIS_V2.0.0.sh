#!/bin/bash

# CIS RHEL 8 Benchmark

# Definir el nombre de usuario que se manejará genericamente
username=defaultuser


# 1.1.1.1
sudo sh -c 'printf "install cramfs /bin/true
" >> /etc/modprobe.d/cramfs.conf'

sudo modprobe -r cramfs


#rmmod cramfs

# 1.1.1.2
sudo sh -c 'printf "install vfat /bin/true
" >> /etc/modprobe.d/vfat.conf'

sudo modprobe -r squashfs

#rmmod vfat

# 1.1.1.3
sudo sh -c 'printf "install udf /bin/true\n
" >> /etc/modprobe.d/udf.conf'

sudo modprobe -r udf

#rmmod udf

# 1.1.2.1
sudo systemctl unmask tmp.mount

sudo sh -c 'printf "tmpfs    /tmp   tmpfs    defaults,nodev,nosuid,noexec       0       0\n
" >> /etc/fstab'
# Recargar /etc/fstab, acá se lleva a cabo lo solicitado en 1.1.3, 1.1.4 y 1.1.5.
sudo mount -a

sudo mount -o remount,nodev,noexec,nosuid /tmp

# 1.1.2.2
#sudo mount -o remount,nodev /tmp

# 1.1.2.3
#sudo mount -o remount,noexec /tmp

# 1.1.2.4
#sudo mount -o remount,nosuid

# Se requiere crear una nueva partición para separar los directorios contemplados desde
# el item 1.1.3.1 hasta el 1.1.8.3.
<<'COMMENTS'
# 1.1.3.1
sudo sh -c 'printf "/dev/sda1    /var   ext4    defaults,nodev,noexec,nosuid       0       0\n
" >> /etc/fstab'
# Recargar /etc/fstab
sudo mount -a

# 1.1.3.2
sudo mount -o remount,nodev /var

# 1.1.3.3
sudo mount -o remount,noexec /var

# 1.1.3.4
sudo mount -o remount,nosuid /var

# 1.1.4.1
# Creating the "subdirectory"
sudo mkdir /var/tmp
#
sudo sh -c 'printf "/dev/sda1    /var/tmp   ext4    defaults,nodev,nosuid,noexec       0       0\n
" >> /etc/fstab'
# Recargar /etc/fstab
sudo mount -a

# 1.1.4.2
sudo mount -o remount,noexec /var/tmp

# 1.1.4.3
sudo mount -o remount,nosuid /var/tmp

# 1.1.4.4
sudo mount -o remount,nodev /var/tmp

# 1.1.5.1
sudo sh -c 'printf "/dev/sda1    /var/log   ext4    defaults,nodev,noexec,nosuid       0       0\n
" >> /etc/fstab'
# Recargar /etc/fstab
sudo mount -a

# 1.1.5.2
sudo mount -o remount,nodev /var

# 1.1.5.3
sudo mount -o remount,noexec /var

# 1.1.5.4
sudo mount -o remount,nosuid /var

# 1.1.6.1
# Creating the "subdirectory"
sudo mkdir /var/log/audit
#
sudo sh -c 'printf "/dev/sda1    /var/log/audit   ext4    defaults,noexec,nodev,nosuid       0       0\n
" >> /etc/fstab'
# Recargar /etc/fstab
sudo mount -a

# 1.1.6.2
sudo mount -o remount,noexec /var/log/audit

# 1.1.6.3
sudo mount -o remount,nodev /var/log/audit

# 1.1.6.4
sudo mount -o remount,nosuid /var/log/audit

# 1.1.7.1
sudo sh -c 'printf "/dev/sda1    /home   ext4    defaults,nodev,nosuid,usrquota,grpquota       0       0\n
" >> /etc/fstab'
# Recargar /etc/fstab
sudo mount -a

# 1.1.7.2
sudo mount -o remount,nodev /home

# 1.1.7.3
sudo mount -o remount,nosuid /home

# 1.1.7.4
sudo mount -o remount,usrquota /home

sudo quotacheck -cugv /home

sudo restorecon /home/aquota.user

sudo quotaon -vug /home

# 1.1.7.5
sudo mount -o remount,grpquota /home

sudo quotacheck -cugv /home

sudo restorecon /home/aquota.group

sudo quotaon -vug /home

# 1.1.8.1
# No es necesario aplicar este criterio, no existe una partición /dev/shm
sudo mount -o remount,nodev /dev/shm

# 1.1.8.2
# No es necesario aplicar este criterio, no existe una partición /dev/shm
sudo mount -o remount,noexec /dev/shm

# 1.1.8.3
# No es necesario aplicar este criterio, no existe una partición /dev/shm
sudo mount -o remount,nosuid /dev/shm
COMMENTS

# 1.1.9
sudo dnf -y remove autofs

sudo systemctl --now disable autofs

# 1.1.10
sudo sh -c 'printf "install usb-storage /bin/true
" >> /etc/modprobe.d/usb_storage.conf'

sudo modprobe -r usb-storage

# 1.2.1 
# Esto requiere interacción con la terminal
# subscription-manager register

# 1.2.2
# "Update your package manager GPG keys" esto es deacuerdo a politicas banco

# 1.2.3
sudo sed -i 's|gpgcheck=.*|gpgcheck=1|g' /etc/dnf/dnf.conf
sudo sed -i "s|gpgcheck=.*|gpgcheck=1|g" /etc/yum.repos.d/*

# 1.2.4
(cat /etc/yum.repos.d/rh-cloud.repo) > package-manager-config.txt

# 1.3.1
sudo dnf -y install aide

sudo aide --init

sudo  mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

# 1.3.2
# aidecheck.service
cat <<EOF > ~/aidecheck.service
[Unit]
Description=Aide Check

[Service]
Type=simple
ExecStart=/usr/sbin/aide --check

[Install]
WantedBy=multi-user.target
EOF


# aidecheck.timer
cat <<EOF > ~/aidecheck.timer
[Unit]
Description=Aide check every day at 5 AM

[Timer]
OnCalendar=*-*-* 05:00:00
Unit=aidecheck.service

[Install]
WantedBy=multi-user.target
EOF

sudo cp ~/aidecheck.timer /etc/systemd/system/aidecheck.timer
sudo cp ~/aidecheck.service /etc/systemd/system/aidecheck.service
rm ~/aidecheck.timer
rm ~/aidecheck.service

# cambiando permisos
sudo chown root:root /etc/systemd/system/aidecheck.*
sudo chmod 0644 /etc/systemd/system/aidecheck.*

sudo systemctl daemon-reload

sudo systemctl enable aidecheck.service
sudo systemctl --now enable aidecheck.timer

# 1.4.1
#sudo grub2-setpassword
#sudo grub2-mkconfig -o "$(dirname "$(find /boot -type f \( -name 'grubenv' -o -name 'grub.conf' -o -name 'grub.cfg' \) -exec sudo grep -Pl '^\h*(kernelopts=|linux|kernel)' {} \;)")/grub.cfg"

# 1.4.2
# Rhel8 usa BIOS, no UEFI
[ -f /boot/grub2/grub.cfg ] && sudo chown root:root /boot/grub2/grub.cfg

[ -f /boot/grub2/grub.cfg ] && sudo chmod og-rwx /boot/grub2/grub.cfg

[ -f /boot/grub2/grubenv ] && sudo chown root:root /boot/grub2/grubenv

[ -f /boot/grub2/grubenv ] && sudo chmod og-rwx /boot/grub2/grubenv

[ -f /boot/grub2/user.cfg ] && sudo chown root:root /boot/grub2/user.cfg

[ -f /boot/grub2/user.cfg ] && sudo chmod og-rwx /boot/grub2/user.cfg

# 1.4.3

if grep -xq "ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue" /usr/lib/systemd/system/rescue.service
then
    echo "1"
else
    cat <<EOF > ~/00-require-auth.conf
    [Service]
    ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue
EOF
    sudo mkdir /etc/systemd/system/rescue.service.d
    sudo mv ~/00-require-auth.conf  /etc/systemd/system/rescue.service.d/
    echo "2"
fi

# 1.5.1
sudo sed -i "s|#Storage=.*|Storage=none|g" /etc/systemd/coredump.conf

# 1.5.2
sudo sed -i "s|#ProcessSizeMax=.*|ProcessSizeMax=0|g" /etc/systemd/coredump.conf

# 1.5.3
sudo bash -c 'printf "kernel.randomize_va_space = 2\n" >>  /etc/sysctl.d/60-kernel_sysctl.conf'

sudo sysctl -w kernel.randomize_va_space=2

# 1.6.1.1
sudo dnf -y install libselinux

# 1.6.1.2
sudo grubby --update-kernel ALL --remove-args 'selinux=0 enforcing=0'

# 1.6.1.3
sudo sed -i "s|SELINUXTYPE=.*|SELINUXTYPE=targeted|g" /etc/systemd/coredump.conf

# 1.6.1.4
sudo setenforce 1
#sudo setenforce 0
sudo sed -i "s|SELINUX=.*|SELINUX=enforcing|g"  /etc/selinux/config
#sudo sed -i "s|SELINUX=.*|SELINUX=permissive|g" /etc/selinux/config

# 1.6.1.5
sudo setenforce 1
sudo sed -i "s|SELINUX=.*|SELINUX=enforcing|g"  /etc/selinux/config

# 1.6.1.6
(sudo ps -eZ | sudo grep unconfined_service_t) > unconfined-service.txt

# 1.6.1.7
sudo dnf -y remove setroubleshoot

# 1.6.1.8
sudo dnf -y remove mcstrans

# 1.7.1
# ¿Se usará mensaje de login?
sudo rm /etc/motd

# 1.7.2
sudo truncate -s 0 /etc/issue

sudo bash -c 'printf "Authorized uses only. All activity may be monitored and reported.\n" >> /etc/issue'

# 1.7.3
sudo truncate -s 0 /etc/issue.net

sudo bash -c 'printf "Authorized uses only. All activity may be monitored and reported.\n" >> /etc/issue.net'

# 1.7.4
sudo chown root:root /etc/motd

sudo chmod u-x,go-wx /etc/motd

# 1.7.5
sudo chown root:root /etc/issue

sudo chmod u-x,go-wx /etc/issue

# 1.7.6
sudo chown root:root /etc/issue.net

sudo chmod u-x,go-wx /etc/issue.net

# 1.8.1
sudo dnf -y remove gdm

# Los siguientes puntos no aplican si se elimina gdm en 1.8.1
<< COMMENTS
# 1.8.2
cat <<EOF > ~/gdm
user-db:user
system-db:gdm
file-db:/usr/share/gdm/greeter-dconf-defaults
EOF

sudo mv ~/gdm /etc/dconf/profile

cat <<EOF > ~/01-banner-message
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized users only. All activity may be monitored and reported'
EOF

sudo mv ~/gdm /etc/dconf/profile

sudo dconf update

# 1.8.3
cat <<EOF > ~/00-login-screen
[org/gnome/login-screen]
# Do not show the user list
disable-user-list=true
EOF

sudo mv ~/00-login-screen /etc/dconf/db/gdm.d

sudo dconf update

# 1.8.4
if grep -xq "#Enable=.*" /etc/gdm/custom.conf
then
    echo "1"
else
    sudo sed -i "s|Enable=.*||g"  /etc/gdm/custom.conf
    echo "2"
fi

# 1.8.5
cat << EOF >> ~/00-media-automount
[org/gnome/desktop/media-handling]
automount=false
automount-open=false
EOF

sudo mv ~/00-media-automount /etc/dconf/db/local.d/

sudo dconf update
COMMENTS

# 1.9
sudo dnf -y update

# 1.10
sudo update-crypto-policies --set DEFAULT

sudo update-crypto-policies

# 2.1.1
sudo dnf -y install chrony

# 2.1.2
# Definit chrony remote server
#sudo bash -c 'printf "server <remote-server>\n" >> /etc/chrony.conf'

x="OPTIONS=\"-u chrony\""

sudo sed -i "s|OPTIONS=.*|$x|g"  /etc/sysconfig/chronyd

# 2.2.1
sudo dnf -y remove xinetd

# 2.2.2
sudo dnf remove -y xorg-x11-server-common

# 2.2.3
sudo systemctl stop avahi-daemon.socket avahi-daemon.service

sudo dnf remove avahi-autoipd avahi

# 2.2.4
sudo dnf -y remove cups

# 2.2.5
sudo dnf -y remove dhcp-server

# 2.2.6
sudo dnf -y remove bind

# 2.2.7
sudo dnf -y remove ftp

# 2.2.8
sudo dnf -y remove vsftpd

# 2.2.9
sudo dnf -y remove tftp-server

# 2.2.10
sudo dnf -y remove httpd nginx

# 2.2.11
sudo dnf -y remove dovecot cyrus-imapd

# 2.2.12
sudo dnf -y remove samba

# 2.2.13
sudo dnf -y remove squid

# 2.2.14
sudo dnf -y remove net-snmp

# 2.2.15
sudo dnf -y remove ypserv

# 2.2.16
sudo dnf -y remove telnet-server

# 2.2.17
x="inet_interfaces = loopback-only"
if grep -xq "inet_interfaces =.*" /etc/postfix/main.cf
then
    sudo sed -i "s|inet_interfaces =.*|$x|g" /etc/postfix/main.cf
    echo "1"
else
    sudo bash -c 'printf "inet_interfaces = loopback-only\n" >> /etc/postfix/main.cf'
    echo "2"
fi

sudo systemctl restart postfix

# 2.2.18
sudo dnf -y remove nfs-utils

# 2.2.19
sudo dnf -y remove rpcbind

# 2.2.20
sudo dnf -y remove rsync

# 2.3.1
sudo dnf -y remove ypbind

# 2.3.2
sudo dnf -y remove rsh

# 2.3.3
sudo dnf -y remove talk

# 2.3.4
sudo dnf -y remove telnet

# 2.3.5
sudo dnf -y remove openldap-clients

# 2.3.6
sudo dnf -y remove tftp

# 2.4
(sudo lsof -i -P -n | sudo grep -v "(ESTABLISHED)") > nonessential-services.txt


# 3.1.1
sudo grubby --update-kernel ALL --args 'ipv6.disable=1'

# 3.1.2
sudo bash -c 'printf "install sctp /bin/true\n" >> /etc/modprobe.d/sctp.conf'

# 3.1.3
sudo bash -c 'printf "install dccp /bin/true\n" >> /etc/modprobe.d/dccp.conf'

# 3.1.4
cat << \EOF >> ~/disable-wireless-interfaces.sh
#!/usr/bin/env bash
{
 if command -v nmcli >/dev/null 2>&1 ; then
    nmcli radio all off
 else
    if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
        mname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename "$(readlink -f "$driverdir"/device/driver/module)";done | sort -u)
        for dm in $mname; do
        echo "install $dm /bin/true" >> /etc/modprobe.d/disable_wireless.conf
        done
    fi
 fi
}
EOF

# 3.2.1
# IPv6 fue deshabilitado en 3.1.1
sudo bash -c 'printf "net.ipv4.ip_forward = 0\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo sysctl -w net.ipv4.ip_forward=0

sudo sysctl -w net.ipv4.route.flush=1

# 3.2.2
cat << \EOF >> ~/60-netipv4_sysctl.conf
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
EOF

sudo mv ~/60-netipv4_sysctl.conf  /etc/sysctl.d/

sudo sysctl -w net.ipv4.conf.all.send_redirects=0

sudo sysctl -w net.ipv4.conf.default.send_redirects=0

sudo sysctl -w net.ipv4.route.flush=1

# 3.3.1
sudo bash -c 'printf "net.ipv4.conf.all.accept_source_route = 0\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo bash -c 'printf "net.ipv4.conf.default.accept_source_route = 0\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo sysctl -w net.ipv4.conf.all.accept_source_route=0

sudo sysctl -w net.ipv4.conf.default.accept_source_route=0

sudo sysctl -w net.ipv4.route.flush=1

# 3.3.2
sudo bash -c 'printf "net.ipv4.conf.all.accept_redirects = 0\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo bash -c 'printf "net.ipv4.conf.default.accept_redirects = 0\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

sudo sysctl -w net.ipv4.conf.default.accept_redirects=0

sudo sysctl -w net.ipv4.route.flush=1

# 3.3.3
sudo bash -c 'printf "net.ipv4.conf.all.secure_redirects = 0\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo bash -c 'printf "net.ipv4.conf.default.secure_redirects = 0\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo sysctl -w net.ipv4.conf.all.secure_redirects=0

sudo sysctl -w net.ipv4.conf.default.secure_redirects=0

sudo sysctl -w net.ipv4.route.flush=1

# 3.3.4
sudo bash -c 'printf "net.ipv4.conf.all.log_martians = 1\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo bash -c 'printf "net.ipv4.conf.default.log_martians = 1\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo sysctl -w net.ipv4.conf.all.log_martians=1

sudo sysctl -w net.ipv4.conf.default.log_martians=1

sudo sysctl -w net.ipv4.route.flush=1

# 3.3.5
sudo bash -c 'printf "net.ipv4.icmp_echo_ignore_broadcasts = 1\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

sudo sysctl -w net.ipv4.route.flush=1

# 3.3.6
sudo bash -c 'printf "net.ipv4.icmp_ignore_bogus_error_responses = 1\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

sudo sysctl -w net.ipv4.route.flush=1

# 3.3.7
sudo bash -c 'printf "net.ipv4.conf.all.rp_filter = 1\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo bash -c 'printf "net.ipv4.conf.default.rp_filter = 1\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo sysctl -w net.ipv4.conf.all.rp_filter=1

sudo sysctl -w net.ipv4.conf.default.rp_filter=1

sudo sysctl -w net.ipv4.route.flush=1

# 3.3.8
sudo bash -c 'printf "net.ipv4.tcp_syncookies = 1\n" >> /etc/sysctl.d/60-netipv4_sysctl.conf'

sudo sysctl -w net.ipv4.tcp_syncookies=1

sudo sysctl -w net.ipv4.route.flush=1

# 3.3.9
# IPv6 fue deshabilitado en 3.1.1
# Verificar si se quedará deshabilitado
<< COMMENTS
cat << \EOF >> ~/60-netipv6_sysctl.conf
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
EOF

sudo mv ~/60-netipv6_sysctl.conf  /etc/sysctl.d/

sudo sysctl -w net.ipv6.conf.all.accept_ra=0

sudo sysctl -w net.ipv6.conf.default.accept_ra=0

sudo sysctl -w net.ipv6.route.flush=1
COMMENTS

# 3.4.1.1
sudo dnf -y install firewalld iptables

# 3.4.1.2
sudo systemctl stop iptables

sudo systemctl stop ip6tables

sudo dnf -y remove iptables-services

# 3.4.1.3
# no se puede eliminar nftables, co-dependencia con firewalld
sudo systemctl --now mask nftables
#sudo dnf -y remove nftables

# 3.4.1.4
sudo systemctl unmask firewalld

sudo systemctl --now enable firewalld

# 3.4.1.5
sudo firewall-cmd --set-default-zone=public

# 3.4.1.6
# sudo firewall-cmd --zone=<Zone NAME> --change-interface=<INTERFACE NAME>

# 3.4.1.7
#sudo firewall-cmd --remove-service=<service>

#sudo firewall-cmd --remove-port=<port-number>/<port-type>

# 3.4.2
# Se saltará toda la sección 3.4.2 debido a que se debe trabajar firewalld, nftables o iptables (sol uno al tiempo)
# en este caso se trabajará con firewalld (toda la sección 3.4.1)
<< COMMENTS
# 3.4.2.1
sudo dnf -y install nftables

# 3.4.2.2
sudo dnf -y remove firewalld

# 3.4.2.3
sudo systemctl stop iptables

sudo systemctl stop ip6tables

sudo dnf -y remove iptables-services

# 3.4.2.4
sudo iptables -F

# 3.4.2.5
sudo nft create table inet filter

# 3.4.2.6
sudo nft create chain inet filter input { type filter hook input priority 0 \; }

sudo nft create chain inet filter forward { type filter hook forward priority 0 \; }

sudo nft create chain inet filter output { type filter hook output priority 0 \; }

# 3.4.2.7
sudo nft add rule inet filter input iif lo accept

sudo nft create rule inet filter input ip saddr 127.0.0.0/8 counter drop

# 3.4.2.8
sudo nft add rule inet filter input ip protocol tcp ct state established accept

sudo nft add rule inet filter input ip protocol udp ct state established accept

sudo nft add rule inet filter input ip protocol icmp ct state established accept

sudo nft add rule inet filter output ip protocol tcp ct state new,related,established accept

sudo nft add rule inet filter output ip protocol udp ct state new,related,established accept

sudo nft add rule inet filter output ip protocol icmp ct state new,related,established accept

# 3.4.2.9
sudo nft chain inet filter input { policy drop \; }

sudo nft chain inet filter forward { policy drop \; }

sudo nft chain inet filter output { policy drop \; }

# 3.4.2.10
sudo systemctl enable nftables

# 3.4.2.11
sudo bash -c 'printf "include "/etc/nftables/nftables.rules"\n" >> /etc/sysconfig/nftables.conf'

COMMENTS

# 3.4.3
# Se saltará toda la sección 3.4.3 debido a que se debe trabajar firewalld, nftables o iptables (sol uno al tiempo)
# en este caso se trabajará con firewalld (toda la sección 3.4.1)
<< COMMENTS
#  3.4.3.1.1
dnf install iptables iptables-services

# 3.4.3.1.2
sudo dnf -y remove nftables

# 3.4.3.1.3
sudo yum -y remove firewalld

# 3.4.3.2.1
sudo iptables -A INPUT -i lo -j ACCEPT

sudo iptables -A OUTPUT -o lo -j ACCEPT

sudo iptables -A INPUT -s 127.0.0.0/8 -j DROP

# 3.4.3.2.2
sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

# 3.4.3.2.3
(ss -4tuln) > opened-ports-IPv4.txt

(sudo  iptables -L INPUT -v -n) > firewall-rules-IPv4.txt

# 3.4.3.2.4
sudo iptables -P INPUT DROP

sudo iptables -P OUTPUT DROP

sudo iptables -P FORWARD DROP

# 3.4.3.2.5
sudo iptables -L

sudo service iptables save

# 3.4.3.2.6
systemctl --now enable iptables
COMMENTS

# 3.4.3.3
# Se saltará toda la sección 3.4.3.3 debido a que se deshabilitó IPv6 en 3.1.1
<< COMMENTS
# 3.4.3.3.1
sudo ip6tables -A INPUT -i lo -j ACCEPT

sudo ip6tables -A OUTPUT -o lo -j ACCEPT

suddo ip6tables -A INPUT -s ::1 -j DROP

# 3.4.3.3.2
sudo ip6tables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT

sudo ip6tables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT

sudo ip6tables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT

sudo ip6tables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT

sudo ip6tables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT

sudo ip6tables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

# 3.4.3.3.3
(ss -6tuln) > opened-ports-IPv6.txt

(sudo ip6tables -L INPUT -v -n) > firewall-rules-IPv6.txt

# 3.4.3.3.4
sudo ip6tables -P INPUT DROP

sudo ip6tables -P OUTPUT DROP

sudo ip6tables -P FORWARD DROP

# 3.4.3.3.5
sudo ip6tables -L

sudo service ip6tables save

# 3.4.3.3.6
sudo systemctl --now start ip6tables
COMMENTS


# 4.1.1.1
sudo dnf -y install audit

# 4.1.1.2
sudo systemctl --now enable auditd

# 4.1.1.3
sudo grubby --update-kernel ALL --args 'audit=1'

# 4.1.1.4
sudo grubby --update-kernel ALL --args 'audit_backlog_limit=8192'

# 4.1.2.1
x="max_log_file = 8"

sudo sed -i "s|max_log_file =.*|$x|g" /etc/audit/auditd.conf

#4.1.2.2
x="max_log_file_action = keep_logs"

sudo sed -i "s|max_log_file_action =.*|$x|g" /etc/audit/auditd.conf

# 4.1.2.3
x="space_left_action = email"

sudo sed -i "s|space_left_action =.*|$x|g" /etc/audit/auditd.conf

x="action_mail_acct = root"

sudo sed -i "s|action_mail_acct =.*|$x|g" /etc/audit/auditd.conf

x="admin_space_left_action = halt"

sudo sed -i "s|admin_space_left_action =.*|$x|g" /etc/audit/auditd.conf

# 4.1.3.1
cat <<EOF > ~/50-scope.rules
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
EOF

sudo mv ~/50-scope.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.2
cat <<EOF > ~/50-user_emulation.rules
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation 
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
EOF

sudo mv ~/50-user_emulation.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.3
SUDO_LOG_FILE=$(sudo grep -r logfile /etc/sudoers* | sudo sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g')

SUDO_LOG_FILE_ESCAPED=$(sudo grep -r logfile /etc/sudoers* | sudo sed -e 's/.*logfile=//;s/,? .*//' -e 's/"//g' -e 's|/|\\/|g')

[ -n "${SUDO_LOG_FILE_ESCAPED}" ] && printf "-w ${SUDO_LOG_FILE} -p wa -k sudo_log_file" >> /etc/audit/rules.d/50-sudo.rules || printf "ERROR: Variable 'SUDO_LOG_FILE_ESCAPED' is unset.\n"

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi


# 4.1.3.4
cat <<EOF > ~/50-time-change.rules
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
EOF

sudo mv ~/50-time-change.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.5
cat <<EOF > ~/50-system_local.rules
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
EOF

sudo mv ~/50-system_local.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi


# 4.1.3.6
touch ~/50-privileged.rules

build_audit_rules()
(
 UID_MIN=$(sudo awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)
 AUDIT_RULE_FILE="./50-privileged.rules"
 NEW_DATA=()
 for PARTITION in $(sudo findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | sudo grep -Pv "noexec|nosuid" | sudo awk '{print $1}'); do readarray -t DATA < <(sudo find "${PARTITION}" -xdev -perm /6000 -type f | sudo awk -v UID_MIN=${UID_MIN} '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>="UID_MIN" -F auid!=unset -k privileged" }')
 for ENTRY in "${DATA[@]}"; do
 NEW_DATA+=("${ENTRY}")
 done
 done
 readarray &> /dev/null -t OLD_DATA < "${AUDIT_RULE_FILE}"
 COMBINED_DATA=( "${OLD_DATA[@]}" "${NEW_DATA[@]}" )
 printf '%s\n' "${COMBINED_DATA[@]}" | sort -u > "${AUDIT_RULE_FILE}"
)

build_audit_rules

sudo mv ~/50-privileged.rules /etc/audit/rules.d

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.7
UID_MIN=$(sudo awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

[ -n "${UID_MIN}" ] && sudo printf "
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
-a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
" >> 50-access.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n"

sudo mv ~/50-access.rules /etc/audit/rules.d/

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.8
printf "
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
" >> ~/50-identity.rules

sudo mv ~/50-identity.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.9
UID_MIN=$(sudo awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
-a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
" >> ~/50-perm_mod.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n"

sudo mv ~/50-perm_mod.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi


# 4.1.3.10
UID_MIN=$(sudo awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
" >> ~/50-perm_mod.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n"

sudo mv ~/50-perm_mod.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.11
printf "
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
" >> 50-session.rules

sudo mv 50-session.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.12
printf "
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
" >> ~/50-login.rules

sudo mv ~/50-login.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.13
UID_MIN=$(sudo awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
-a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
" >> ~/50-delete.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n"

sudo mv ~/50-delete.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.14
printf "
-w /etc/selinux -p wa -k MAC-policy
-w /usr/share/selinux -p wa -k MAC-policy
" >> ~/50-MAC-policy.rules

sudo mv ~/50-MAC-policy.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.15
UID_MIN=$(sudo awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

 [ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> ~/50-perm_chng.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n"

sudo mv ~/50-perm_chng.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.16
UID_MIN=$(sudo awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

[ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> ~/50-priv_cmd.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n"

sudo mv ~/50-priv_cmd.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.17
UID_MIN=$(sudo awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

[ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
" >> ~/50-perm_chng.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n"

sudo mv ~/50-perm_chng.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.18
UID_MIN=$(sudo awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

[ -n "${UID_MIN}" ] && printf "
-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k usermod
" >> ~/50-usermod.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n"

sudo mv ~/50-usermod.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.19
UID_MIN=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)

[ -n "${UID_MIN}" ] && printf "
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
" >> ~/50-kernel_modules.rules \
|| printf "ERROR: Variable 'UID_MIN' is unset.\n"

sudo mv ~/50-kernel_modules.rules /etc/audit/rules.d/

sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.1.3.20
sudo bash -c 'printf -- "-e 2\n" >> /etc/audit/rules.d/99-finalize.rules'

# 4.1.3.21
sudo augenrules --load

if [[ $(sudo auditctl -s | sudo grep "enabled") =~ "2" ]]; then printf "Reboot required to load rules\n"; fi

# 4.2.1.1
sudo dnf -y install rsyslog

# 4.2.1.2
sudo systemctl --now enable rsyslog

# 4.2.1.3
sudo sed -i "s|#ForwardToSyslog=.*|ForwardToSyslog=yes|g" /etc/systemd/journald.conf

sudo systemctl restart rsyslog

# 4.2.1.4
# Se lleva a cabo en 4.2.1.5
#sudo bash -c 'printf "\$FileCreateMode 0640\n" >> /etc/rsyslog.conf'
#sudo  systemctl restart rsyslog

# 4.2.1.5
sudo truncate -s 0 /etc/rsyslog.conf

cat <<EOF > ~/rsyslog.conf
# rsyslog configuration file

# For more information see /usr/share/doc/rsyslog-*/rsyslog_conf.html
# or latest version online at http://www.rsyslog.com/doc/rsyslog_conf.html
# If you experience problems, see http://www.rsyslog.com/doc/troubleshoot.html

#### MODULES ####

module(load="imuxsock"    # provides support for local system logging (e.g. via logger command)
       SysSock.Use="off") # Turn off message reception via local log socket;
                          # local messages are retrieved through imjournal now.
module(load="imjournal"             # provides access to the systemd journal
       StateFile="imjournal.state") # File to store the position in the journal
#module(load="imklog") # reads kernel messages (the same are read from journald)
#module(load="immark") # provides --MARK-- message capability

# Provides UDP syslog reception
# for parameters see http://www.rsyslog.com/doc/imudp.html
#module(load="imudp") # needs to be done just once
#input(type="imudp" port="514")

# Provides TCP syslog reception
# for parameters see http://www.rsyslog.com/doc/imtcp.html
#module(load="imtcp") # needs to be done just once
#input(type="imtcp" port="514")

#### GLOBAL DIRECTIVES ####

# Where to place auxiliary files
global(workDirectory="/var/lib/rsyslog")

# Use default timestamp format
module(load="builtin:omfile" Template="RSYSLOG_TraditionalFileFormat")

# Include all config files in /etc/rsyslog.d/
include(file="/etc/rsyslog.d/*.conf" mode="optional")

#### RULES ####

# Log all kernel messages to the console.
# Logging much else clutters up the screen.
#kern.*                                                 /dev/console

# Log anything (except mail) of level info or higher.
# Don't log private authentication messages!
*.info;mail.none;authpriv.none;cron.none                /var/log/messages

# The authpriv file has restricted access.
auth,authpriv.*                                              /var/log/secure

# Log all the mail messages in one place.
mail.*                                                  -/var/log/mail
mail.info                                                  -/var/log/mail.info
mail.warning                                                  -/var/log/mail.warn
mail.err                                                  -/var/log/mail.err

# Log cron stuff
cron.*                                                  /var/log/cron

# Everybody gets emergency messages
*.emerg                                                 :omusrmsg:*

# Save news errors of level crit and higher in a special file.
news.crit                                          -/var/log/news/news.crit
uucp                                          /var/log/spooler
news.err                                          -/var/log/news/news.err
news.notice                                          -/var/log/news/news.notice

# Save boot messages also to boot.log
local0,local1.*                                                /var/log/localmessages
local2,local3.*                                                /var/log/localmessages
local4,local5.*                                                /var/log/localmessages
local6,local7.*                                                /var/log/localmessages

# ### sample forwarding rule ###
#action(type="omfwd"
# An on-disk queue is created for this action. If the remote host is
# down, messages are spooled to disk and sent when it is up again.
#queue.filename="fwdRule1"       # unique name prefix for spool files
#queue.maxdiskspace="1g"         # 1gb space limit (use as much as possible)
#queue.saveonshutdown="on"       # save messages to disk on shutdown
#queue.type="LinkedList"         # run asynchronously
#action.resumeRetryCount="-1"    # infinite retries if host is down
# Remote Logging (we use TCP for reliable delivery)
# remote_host is: name/ip, e.g. 192.168.0.1, port optional e.g. 10514
#Target="remote_host" Port="XXX" Protocol="tcp")

*.=warning;*.=err                                          -/var/log/warn
*.crit                                          -/var/log/news/warn
*.*;mail.none;news.none                                          -/var/log/news/messages
EOF

sudo cp ~/rsyslog.conf /etc/rsyslog.conf

sudo rm ~/rsyslog.conf

sudo bash -c 'printf "\$FileCreateMode 0640\n" >> /etc/rsyslog.conf'

sudo systemctl restart rsyslog

# 4.2.1.6
sudo bash -c 'printf "*.* action(type="omfwd" target="192.168.2.100" port="514" protocol="tcp" action.resumeRetryCount="100" queue.type="LinkedList" queue.size="1000")" >> /etc/rsyslog.conf'

sudo systemctl restart rsyslog

# 4.2.1.7
if sudo grep -xq "#module(load=\"imtcp\").*" /etc/rsyslog.conf
then
    echo "Nada por corregir, el entry \"module(load=\"imtcp\")\" no existe en /etc/rsyslog.conf"
else
    sudo sed -i "s|module(load=\"imtcp\")|#module(load=\"imtcp\")|g" /etc/rsyslog.conf
    echo "Se eliminó el entry \"module(load=\"imtcp\")\" del archivo /etc/rsyslog.conf"
fi

sudo systemctl restart rsyslog

# 4.2.2.1.1
sudo dnf -y install systemd-journal-remote

# 4.2.2.1.2
# Definir remote host que recibirrá logs
#sudo sed -i "s|# URL=.*|URL=192.168.50.42|g" /etc/rsyslog.conf
#sudo sed -i "s|# ServerKeyFile=.*|ServerKeyFile=/etc/ssl/private/journal-upload.pem|g" /etc/rsyslog.conf
#sudo sed -i "s|# ServerCertificateFile=.*|ServerCertificateFile=/etc/ssl/certs/journal-upload.pem|g" /etc/rsyslog.conf
#sudo sed -i "s|# TrustedCertificateFile=.*|TrustedCertificateFile=/etc/ssl/ca/trusted.pem|g" /etc/rsyslog.conf

#sudo systemctl restart systemd-journal-upload

# 4.2.2.1.3
sudo systemctl --now enable systemd-journal-upload.service

# 4.2.2.1.4
sudo systemctl --now mask systemd-journal-remote.socket

# 4.2.2.2
# Este servicio está habilitado por defecto luego de ser instalado en 4.2.2.1.1

# 4.2.2.3
sudo sed -i "s|#Compress=.*|Compress=yes|g"  /etc/systemd/journald.conf

sudo systemctl restart systemd-journal-upload

# 4.2.2.4
sudo sed -i "s|#Storage.*|Storage=persistent|g"  /etc/systemd/journald.conf

sudo systemctl restart systemd-journal-upload

# 4.2.2.5
sudo sed -i "s|ForwardToSyslog=yes||g"  /etc/systemd/journald.conf

sudo systemctl restart systemd-journal-upload

# 4.2.2.6
# Definir parámetros correspondientes a rotación de logs
#sudo sed -i "s|#SystemMaxUse=.*|SystemMaxUse=|g" /etc/systemd/journald.conf
#sudo sed -i "s|#SystemKeepFree=.*|SystemKeepFree=|g" /etc/systemd/journald.conf
#sudo sed -i "s|#RuntimeMaxUse=.*|RuntimeMaxUse=|g" /etc/systemd/journald.conf
#sudo sed -i "s|#RuntimeKeepFree=.*|RuntimeKeepFree=|g" /etc/systemd/journald.conf
#sudo sed -i "s|#MaxFileSec=.*|MaxFileSec=|g" /etc/systemd/journald.conf

# 4.2.2.7
# Existirá algo a corregir dependiendo de las políticas de banco en este punto específico
sudo chmod 0640 /usr/lib/tmpfiles.d/systemd.conf

# 4.2.3
sudo find /var/log/ -type f -perm /g+wx,o+rwx -exec chmod --changes g-wx,o-rwx "{}" +

# 4.3
# Definir política de rotación de logs


# 5.1.1
sudo systemctl --now enable crond

# 5.1.2
sudo chown root:root /etc/crontab

sudo chmod og-rwx /etc/crontab

# 5.1.3
sudo chown root:root /etc/cron.hourly

sudo chmod og-rwx /etc/cron.hourly

# 5.1.4
sudo chown root:root /etc/cron.daily

sudo chmod og-rwx /etc/cron.daily

# 5.1.5
sudo chown root:root /etc/cron.weekly

sudo chmod og-rwx /etc/cron.weekly

# 5.1.6
sudo chown root:root /etc/cron.monthly

sudo chmod og-rwx /etc/cron.monthly

# 5.1.7
sudo chown root:root /etc/cron.d

sudo chmod og-rwx /etc/cron.d

# 5.1.8
cat <<EOF > ~/cron-restricted.sh
#!/usr/bin/env bash

cron_fix()
{
 if rpm -q cronie >/dev/null; then
    [ -e /etc/cron.deny ] && rm -f /etc/cron.deny
    [ ! -e /etc/cron.allow ] && touch /etc/cron.allow
    chown root:root /etc/cron.allow
    chmod u-x,go-rwx /etc/cron.allow
 else
    echo "cron is not installed on the system"
 fi
}

cron_fix
EOF

chmod +x ~/cron-restricted.sh

sudo bash ~/cron-restricted.sh

# 5.1.9
cat <<EOF > ~/at-restricted.sh
#!/usr/bin/env bash

at_fix()
{
 if rpm -q at >/dev/null; then
    [ -e /etc/at.deny ] && rm -f /etc/at.deny
    [ ! -e /etc/at.allow ] && touch /etc/at.allow
    chown root:root /etc/at.allow
    chmod u-x,go-rwx /etc/at.allow
 else
    echo "at is not installed on the system"
 fi
}

at_fix
EOF

chmod +x ~/at-restricted.sh

sudo bash ~/at-restricted.sh

# 5.2.1
sudo chown root:root /etc/ssh/sshd_config

sudo chmod og-rwx /etc/ssh/sshd_config

# 5.2.2
sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,g-wx,o-rwx {} \;

sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:ssh_keys {} \;

# 5.2.3
sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;

sudo find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;

# 5.2.4
#sudo bash -c 'printf "AllowGroups <grouplist>\n" >> /etc/ssh/sshd_config'
#sudo bash -c 'printf "AllowUsers <userlist>\n" >> /etc/ssh/sshd_config'
#sudo bash -c 'printf "DenyUsers <userlist>\n" >> /etc/ssh/sshd_config'
#sudo bash -c 'printf "DenyGroups <grouplist>\n" >> /etc/ssh/sshd_config'

# 5.2.5
sudo sed -i "s|#LogLevel.*|LogLevel VERBOSE|g" /etc/ssh/sshd_config

# 5.2.6
sudo sed -i "s|UsePAM.*|UsePAM yes|g" /etc/ssh/sshd_config

# 5.2.7
sudo sed -i "s|PermitRootLogin.*|PermitRootLogin no|g" /etc/ssh/sshd_config

# 5.2.8
sudo sed -i "s|#HostbasedAuthentication.*|HostbasedAuthentication no|g" /etc/ssh/sshd_config

# 5.2.9
sudo sed -i "s|#PermitEmptyPasswords.*|PermitEmptyPasswords no|g" /etc/ssh/sshd_config

# 5.2.10
sudo sed -i "s|#PermitUserEnvironment.*|PermitUserEnvironment no|g" /etc/ssh/sshd_config

# 5.2.11
sudo sed -i "s|#IgnoreRhosts.*|IgnoreRhosts yes|g" /etc/ssh/sshd_config

# 5.2.12
sudo sed -i "s|X11Forwarding.*|X11Forwarding no|g" /etc/ssh/sshd_config

# 5.2.13
sudo sed -i "s|#AllowTcpForwarding.*|AllowTcpForwarding no|g" /etc/ssh/sshd_config

# 5.2.14
sudo sed -ri "s/^\s*(CRYPTO_POLICY\s*=.*)$/# \1/" /etc/sysconfig/sshd

sudo systemctl reload sshd

# 5.2.15
sudo sed -i "s|#Banner.*|#Banner /etc/issue.net|g" /etc/ssh/sshd_config

# 5.2.16
sudo sed -i "s|#MaxAuthTries.*|MaxAuthTries 4|g" /etc/ssh/sshd_config

# 5.2.17
sudo sed -i "s|#MaxStartups.*|MaxStartups 10:30:60|g" /etc/ssh/sshd_config

# 5.2.18
sudo sed -i "s|#MaxSessions.*|MaxSessions 10|g" /etc/ssh/sshd_config

# 5.2.19
sudo sed -i "s|#LoginGraceTime.*|LoginGraceTime 60|g" /etc/ssh/sshd_config

# 5.2.20
sudo sed -i "s|ClientAliveInterval.*|ClientAliveInterval 300|g" /etc/ssh/sshd_config

sudo sed -i "s|#ClientAliveCountMax.*|ClientAliveCountMax 3|g" /etc/ssh/sshd_config

# 5.3.1
sudo dnf -y install sudo

# 5.3.2
sudo bash -c "echo 'Defaults use_pty' >> /etc/sudoers"

# 5.3.3
sudo bash -c "echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers"

# 5.3.4
(sudo grep -r "^[^#].*NOPASSWD" /etc/sudoers*) > ~/no-password.txt

# 5.3.5
(sudo grep -r "^[^#].*\!authenticate" /etc/sudoers*) > ~/re-auth.txt

# 5.3.6
(sudo  grep -roP "timestamp_timeout=\K[0-9]*" /etc/sudoers*) > sudo-auth-timeout.txt

x=$(sudo -V | grep "Authentication timestamp timeout:")

printf "$x\n" >> sudo-auth-timeout.txt

# 5.3.7
sudo groupadd sugroup

sudo bash -c 'printf "auth required pam_wheel.so use_uid group=sugroup\n" >> /etc/pam.d/su'

# 5.4.1
# sudo dnf -y install authselect
sudo authselect create-profile custom-profile -b sssd --symlink-meta

sudo authselect select custom/custom-profile with-sudo with-faillock without-nullok --force

# 5.4.2
sudo authselect enable-feature with-faillock

sudo authselect apply-changes

# 5.5.1
sudo sed -i "s|# minlen =.*|minlen = 14|g" /etc/security/pwquality.conf

sudo sed -i "s|# minclass = 0.*|minclass = 4|g" /etc/security/pwquality.conf

# 5.5.2
sudo sed -i "s|# deny =.*|deny = 5|g" /etc/security/faillock.conf

sudo sed -i "s|# unlock_time =.*|unlock_time = 900|g" /etc/security/faillock.conf

# 5.5.3
cat << \EOF > ~/pass-reuse-limited.sh
#!/usr/bin/env bash
{
 file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | sudo grep 'custom/')/system-auth"
 if ! sudo grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=([5-9]|[1-9][0-9]+)\b.*$' "$file"; then
    if sudo grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=\d+\b.*$' "$file"; then
        sudo sed -ri 's/^\s*(password\s+(requisite|required|sufficient)\s+pam_pwhistory\.so\s+([^#\n\r]+\s+)?)(remember=\S+\s*)(\s+.*)?$/\1 remember=5 \5/' $file
    elif sudo grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?.*$' "$file"; then
        sudo sed -ri '/^\s*password\s+(requisite|required|sufficient)\s+pam_pwhistory\.so/ s/$/ remember=5/' $file
    else
        sudo sed -ri '/^\s*password\s+(requisite|required|sufficient)\s+pam_unix\.so/i password required pam_pwhistory.so remember=5 use_authtok' $file
    fi
 fi
 if ! sudo grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_unix\.so\h+([^#\n\r]+\h+)?remember=([5-9]|[1-9][0-9]+)\b.*$' "$file"; then
    if sudo grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_unix\.so\h+([^#\n\r]+\h+)?remember=\d+\b.*$' "$file"; then
        sudo sed -ri 's/^\s*(password\s+(requisite|required|sufficient)\s+pam_unix\.so\s+([^#\n\r]+\s+)?)(remember=\S+\s*)(\s+.*)?$/\1 remember=5 \5/' $file
    else
        sudo sed -ri '/^\s*password\s+(requisite|required|sufficient)\s+pam_unix\.so/ s/$/ remember=5/' $file
    fi
 fi
 sudo authselect apply-changes
}
EOF

chmod +x ~/pass-reuse-limited.sh

sudo bash ~/pass-reuse-limited.sh

# 5.5.4
sudo sed -i "s|crypt_style =.*|crypt_style = sha512|g" /etc/libuser.conf

sudo sed -i "s|ENCRYPT_METHOD.*|ENCRYPT_METHOD SHA512|g" /etc/login.defs

cat << \EOF > ~/pam-unix-sha512.sh
#!/usr/bin/env bash

for fn in system-auth password-auth; do
 file="/etc/authselect/$(head -1 /etc/authselect/authselect.conf | sudo grep 'custom/')/$fn"
 if ! sudo grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_unix\.so(\h+[^#\n\r]+)?\h+sha512\b.*$' "$file"; then
    if grep -Pq -- '^\h*password\h+(requisite|required|sufficient)\h+pam_unix\.so(\h+[^#\n\r]+)?\h+(md5|blowfish|bigcrypt|sha256)\b.*$' "$file"; then
        sudo sed -ri 's/(md5|blowfish|bigcrypt|sha256)/sha512/' "$file"
    else
        sudo sed -ri 's/(^\s*password\s+(requisite|required|sufficient)\s+pam_unix.so\s+)(.*)$/\1sha512 \3/' $file
    fi
 fi
done

sudo authselect apply-changes
EOF

chmod +x ~/pam-unix-sha512.sh

sudo bash ~/pam-unix-sha512.sh

# 5.6.1.1
sudo sed -i "s|PASS_MAX_DAYS.*|PASS_MAX_DAYS   365|g" /etc/login.defs

sudo chage --maxdays 365 $username

# 5.6.1.2
sudo sed -i "s|PASS_MIN_DAYS.*|PASS_MIN_DAYS   7|g" /etc/login.defs

sudo chage --mindays 7 $username

# 5.6.1.3
sudo sed -i "s|PASS_WARN_AGE.*|PASS_WARN_AGE   7|g" /etc/login.defs

sudo chage --warndays 1 $username

# 5.6.1.4
sudo useradd -D -f 30

sudo chage --inactive 30 $username

# 5.6.1.5
(sudo awk -F: '/^[^:]+:[^!*]/{print $1}' /etc/shadow | while read -r usr; \
do change=$(date -d "$(chage --list $usr | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')" +%s); \
if [[ "$change" -gt "$(date +%s)" ]]; then \
echo "User: \"$usr\" last password change was \"$(chage --list $usr | grep '^Last password change' | cut -d: -f2)\""; fi; done) > last-pass-change-txt

# 5.6.2
sudo awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && \
$1!~/^\+/ && $3<'"$(sudo awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && \
$7!="'"$(which nologin)"'" && $7!="/bin/false") {print $1}' /etc/passwd | \
while read user; do
 sudo usermod -s $(which nologin) $user
 echo $user 
done

# 5.6.4
sudo usermod -g 0 root

# 5.6.5
cat << \EOF > ~/setumask.sh
umask 027
EOF

sudo mv ~/setumask.sh /etc/profile.d/

sudo chmod +x /etc/profile.d/setumask.sh

(grep -RPi '(^|^[^#]*)\s*umask\s+([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][0-6]\b|[0-7][01][0-7]\b|[0-7][0-7][0-6]\b|(u=[rwx]{0,3},)?(g=[rwx]{0,3},)?o=[rwx]+\b|(u=[rwx]{1,3},)?g=[^rx]{1,3}(,o=[rwx]{0,3})?\b)' /etc/login.defs /etc/profile* /etc/bashrc*) > returned-umask.txt

sudo sed -i "s|UMASK.*|UMASK           027|g" /etc/login.defs

sudo sed -i "s|USERGROUPS_ENAB.*|USERGROUPS_ENAB no|g" /etc/login.defs

sudo bash -c 'printf "session     optional                                     pam_umask.so\n" >> /etc/pam.d/password-auth'

sudo bash -c 'printf "session     optional                                     pam_umask.so\n" >> /etc/pam.d/system-auth'

# 6.1.1
# Este criterio aplica si hay la necesidad de verificar si algún paquete rpm específico fue correctamente instalado
#(rpm -Va --nomtime --nosize --nomd5 --nolinkto > <filename>) > rpm-package-audit.txt

# 6.1.2
sudo df --local -P | sudo awk '{if (NR!=1) print $6}' | sudo xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | sudo xargs -I '{}' chmod a+t '{}'

# 6.1.3
sudo chown root:root /etc/passwd

sudo chmod 644 /etc/passwd

# 6.1.4
sudo chown root:root /etc/shadow

sudo chmod 0000 /etc/shadow

# 6.1.5
sudo chown root:root /etc/group

sudo chmod u-x,g-wx,o-wx /etc/group

# 6.1.6
sudo chown root:root /etc/gshadow

sudo chmod 0000 /etc/gshadow

# 6.1.7
sudo chown root:root /etc/passwd-

sudo chmod u-x,go-wx /etc/passwd-

# 6.1.8
sudo chown root:root /etc/shadow-

sudo chmod 0000 /etc/shadow-

# 6.1.9
sudo chown root:root /etc/group-

sudo chmod u-x,go-wx /etc/group-

# 6.1.10
sudo chown root:root /etc/gshadow-

sudo chmod 0000 /etc/gshadow-

# 6.1.11
(sudo df --local -P | sudo awk '{if (NR!=1) print $6}' | sudo xargs -I '{}' find '{}' -xdev -type f -perm -0002) > world-writable-files.txt

# 6.1.12
(sudo df --local -P | sudo awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nouser) > unowned-directories-files.txt

# 6.1.13
(sudo df --local -P | sudo awk '{if (NR!=1) print $6}' | sudo xargs -I '{}' find '{}' -xdev -nogroup) > ungrouped-directories-files.txt

# 6.1.14
(sudo df --local -P | sudo awk '{if (NR!=1) print $6}' | sudo xargs -I '{}' find '{}' -xdev -type f -perm -4000) > SUID-files.txt

# 6.1.15
(sudo df --local -P | sudo awk '{if (NR!=1) print $6}' | sudo xargs -I '{}' find '{}' -xdev -type f -perm -2000) > SGID-files.txt

# 6.2.1
# No aplica

# 6.2.2
cat << \EOF >  groupsexistin-passwd-group.sh
#!/bin/bash
for i in $(sudo cut -s -d: -f4 /etc/passwd | sort -u ); do
 sudo grep -q -P "^.*?:[^:]*:$i:" /etc/group
 if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
 fi
done
EOF

chmod +x groupsexistin-passwd-group.sh

bash groupsexistin-passwd-group.sh

# 6.2.3
cat << \EOF >  UIDs-duplicate.sh
#!/bin/bash
sudo cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do
 [ -z "$x" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
    users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
    echo "Duplicate UID ($2): $users"
 fi
done
EOF

chmod +x UIDs-duplicate.sh

bash UIDs-duplicate.sh

# 6.2.4
cat << \EOF >  GIDs-duplicate.sh
#!/bin/bash 
sudo cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
 echo "Duplicate GID ($x) in /etc/group"
done
EOF

chmod +x GIDs-duplicate.sh

bash GIDs-duplicate.sh

# 6.2.5
cat << \EOF >  username-duplicate.sh
#!/bin/bash
sudo cut -d: -f1 /etc/passwd | sort | uniq -d | while read x
do echo "Duplicate login name ${x} in /etc/passwd"
done
EOF

chmod +x username-duplicate.sh

bash username-duplicate.sh

# 6.2.6
cat << \EOF >  group-duplicate.sh
#!/bin/bash
sudo cut -d: -f1 /etc/group | sort | uniq -d | while read x
do echo "Duplicate group name ${x} in /etc/group"
done
EOF

chmod +x group-duplicate.sh

bash group-duplicate.sh

# 6.2.7
cat << \EOF >  root-PATH-Integrity.sh
#!/bin/bash
RPCV="$(sudo -Hiu root env | grep '^PATH=' | cut -d= -f2)"
echo "$RPCV" | grep -q "::" && echo "root's path contains a empty directory (::)"
echo "$RPCV" | grep -q ":$" && echo "root's path contains a trailing (:)"
for x in $(echo "$RPCV" | tr ":" " "); do
 if [ -d "$x" ]; then
    ls -ldH "$x" | awk '$9 == "." {print "PATH contains current working directory (.)"} $3 != "root" {print $9, "is not owned by root"} substr($1,6,1) != "-" {print $9, "is group writable"} substr($1,9,1) != "-" {print $9, "is world writable"}'
 else
    echo "$x is not a directory"
 fi
done
EOF

chmod +x root-PATH-Integrity.sh

sudo bash root-PATH-Integrity.sh

# 6.2.8
# No aplica

# 6.2.9
cat << \EOF >  User-home-directory-exist.sh
#!/bin/bash
sudo awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
 if [ ! -d "$dir" ]; then
    echo "User: \"$user\" home directory: \"$dir\" does not exist."
 fi
done
EOF

chmod +x User-home-directory-exist.sh

bash User-home-directory-exist.sh

# En caso de que se desee crear home directory para algún usuario, usar el script comentado abajo
<< COMMENTS
cat << \EOF >  Creating-user-home-directory.sh
#!/bin/bash
sudo awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
 if [ ! -d "$dir" ]; then
    sudo mkdir "$dir"
    sudo chmod g-w,o-wrx "$dir"
    sudo chown "$user" "$dir"
 fi
don
EOF

chmod +x Creating-user-home-directory.sh

bash Creating-user-home-directory.sh
COMMENTS


# 6.2.10
cat << \EOF >  Home-directory-set.sh
#!/bin/bash 
sudo awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
 if [ ! -d "$dir" ]; then
    echo "User: \"$user\" home directory: \"$dir\" does not exist, creating home directory"
    sudo mkdir "$dir"
    sudo chmod g-w,o-rwx "$dir"
    sudo chown "$user" "$dir"
 else
    owner=$(stat -L -c "%U" "$dir")
    if [ "$owner" != "$user" ]; then
        sudo chmod g-w,o-rwx "$dir"
        sudo chown "$user" "$dir"
    fi
 fi
done
EOF

chmod +x Home-directory-set.sh

bash Home-directory-set.sh

# 6.2.11
cat << \EOF >  remove-Home-directory-permissions.sh
#!/bin/bash
sudo awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) {print $6}' /etc/passwd | while read -r dir; do
 if [ -d "$dir" ]; then
    dirperm=$(stat -L -c "%A" "$dir")
    if [ "$(echo "$dirperm" | cut -c6)" != "-" ] || [ "$(echo "$dirperm" | cut -c8)" != "-" ] || [ "$(echo "$dirperm" | cut -c9)" != "-" ] || [ "$(echo "$dirperm" | cut -c10)" != "-" ]; then
        sudo chmod g-w,o-rwx "$dir"
    fi
 fi
done
EOF

chmod +x remove-Home-directory-permissions.sh

bash remove-Home-directory-permissions.sh

# 6.2.12
cat << \EOF >  remove-Dotfiles-permissions.sh
#!/bin/bash
sudo awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
 if [ -d "$dir" ]; then
    for file in "$dir"/.*; do
        if [ ! -h "$file" ] && [ -f "$file" ]; then
            fileperm=$(stat -L -c "%A" "$file")
            if [ "$(echo "$fileperm" | cut -c6)" != "-" ] || [ "$(echo "$fileperm" | cut -c9)" != "-" ]; then
                sudo chmod go-w "$file"
            fi
        fi
    done
 fi
done
EOF

chmod +x remove-Dotfiles-permissions.sh

bash remove-Dotfiles-permissions.sh

# 6.2.13
cat << \EOF >  remove-netrcfiles.sh
#!/bin/bash
sudo awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
 if [ -d "$dir" ]; then
    file="$dir/.netrc"
    [ ! -h "$file" ] && [ -f "$file" ] && rm -f "$file"
 fi
done
EOF

chmod +x remove-netrcfiles.sh

bash remove-netrcfiles.sh

# 6.2.14
cat << \EOF >  remove-forwardfiles.sh
#!/bin/bash 
sudo awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
 if [ -d "$dir" ]; then
    file="$dir/.forward"
    [ ! -h "$file" ] && [ -f "$file" ] && rm -r "$file"
 fi
done
EOF

chmod +x remove-forwardfiles.sh

bash remove-forwardfiles.sh

# 6.2.15
# Es el mismo script de 6.2.13

# 6.2.16
cat << \EOF >  remove-rhostsfiles.sh
#!/bin/bash 
sudo awk -F: '($1!~/(halt|sync|shutdown|nfsnobody)/ && $7!~/^(\/usr)?\/sbin\/nologin(\/)?$/ && $7!~/(\/usr)?\/bin\/false(\/)?$/) { print $6 }' /etc/passwd | while read -r dir; do
 if [ -d "$dir" ]; then
    file="$dir/.rhosts"
    [ ! -h "$file" ] && [ -f "$file" ] && rm -r "$file"
 fi
done
EOF

chmod +x remove-rhostsfiles.sh

bash remove-rhostsfiles.sh

echo "Criterios CIS para Redhat 8 fueron aplicados."