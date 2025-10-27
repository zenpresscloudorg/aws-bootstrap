#!/bin/bash
sudo yum update -y
sudo yum install -y yum-utils ipcalc
sudo yum-config-manager --add-repo https://pkgs.tailscale.com/stable/amazon-linux/2023/tailscale.repo
sudo yum install -y iptables-services tailscale
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.conf
sudo sysctl -p /etc/sysctl.conf
ETH_IFACE=$(ip route | grep default | awk '{print $5}')
iptables -t nat -A POSTROUTING -o $ETH_IFACE -j MASQUERADE
service iptables save
systemctl enable iptables
systemctl start iptables
sudo systemctl enable --now tailscaled
sudo tailscale up --auth-key="$AUTH_KEY" --hostname="$HOSTNAME" --advertise-routes="$ADVERTISE_ROUTES"