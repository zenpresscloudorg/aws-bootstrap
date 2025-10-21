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
# Sustituye AUTH_KEY y HOSTNAME en tu template Terraform
sudo tailscale up --auth-key="$AUTH_KEY" --hostname="$HOSTNAME" --advertise-routes="$ADVERTISE_ROUTES"
NET_DEV=$(ip route | awk '/default/ {print $5; exit}')
CIDR=$(ip -o -f inet addr show $NET_DEV | awk '{print $4}')
NETWORK=$(ipcalc -n $CIDR | awk -F= '/NETWORK/ {print $2}')
IFS=. read n1 n2 n3 n4 <<< "$NETWORK"
ROUTE53_RESOLVER="$n1.$n2.$n3.$((n4 + 2))"
sudo yum install -y dnsmasq
cat <<EOF | sudo tee /etc/dnsmasq.conf
interface=tailscale0
bind-dynamic
no-resolv
# Sustituye DNSMASQ_SERVERS en tu template Terraform
$DNSMASQ_SERVERS
port=53
EOF
sudo systemctl enable dnsmasq
sudo systemctl restart dnsmasq
