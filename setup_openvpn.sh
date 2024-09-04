#!/bin/bash

# Ensure the script runs as root
if [[ "$EUID" -ne 0 ]]; then
  echo "Please run as root or use sudo"
  exit 1
fi

# Step 1: Install necessary packages (OpenVPN, Easy-RSA, UFW, net-tools)
echo "Installing necessary packages..."
apt-get update
apt-get install -y openvpn easy-rsa iptables-persistent ufw net-tools || { echo "Failed to install necessary packages"; exit 1; }

# Step 2: Setup Easy-RSA environment
EASYRSA_DIR="/etc/openvpn/easy-rsa"
if [[ ! -d "$EASYRSA_DIR" ]]; then
  echo "Setting up Easy-RSA..."
  make-cadir "$EASYRSA_DIR"
fi
cd "$EASYRSA_DIR" || exit 1
./easyrsa init-pki

# Step 3: Generate server and client certificates
echo "Generating certificates..."
./easyrsa build-ca nopass
./easyrsa gen-req server nopass
./easyrsa sign-req server server
./easyrsa gen-dh
openvpn --genkey secret pki/ta.key
./easyrsa gen-req client nopass
./easyrsa sign-req client client

# Step 4: Determine the active network interface, IP address, and MTU
echo "Determining active network interface and MTU..."
INTERFACE=$(ip route | grep default | awk '{print $5}')
SERVER_IP=$(ip -4 addr show "$INTERFACE" | grep inet | awk '{print $2}' | cut -d'/' -f1)
MTU=$(netstat -i | grep "$INTERFACE" | awk '{print $4}')

# Replace dots in the IP address with dashes for the file name
ORIGINAL_USER=$(logname)
USER_HOME=$(eval echo "~$ORIGINAL_USER")
OVPN_FILE="$USER_HOME/client-${SERVER_IP//./-}.ovpn"

echo "Detected interface: $INTERFACE, IP: $SERVER_IP, MTU: $MTU"
echo "OVPN file will be saved to: $OVPN_FILE"

# Step 5: Configure OpenVPN server
SERVER_CONF="/etc/openvpn/server.conf"
cat > "$SERVER_CONF" <<EOF
port 443
proto tcp
dev tun
ca $EASYRSA_DIR/pki/ca.crt
cert $EASYRSA_DIR/pki/issued/server.crt
key $EASYRSA_DIR/pki/private/server.key
dh $EASYRSA_DIR/pki/dh.pem
tls-auth $EASYRSA_DIR/pki/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
verb 3
explicit-exit-notify 1
EOF

# Step 6: Configure UFW and enable IPv4 forwarding
echo "Configuring UFW and enabling IP forwarding..."
ufw allow 443/tcp
ufw allow OpenSSH
ufw enable
sed -i '/net.ipv4.ip_forward/s/^#//g' /etc/sysctl.conf
sysctl -p

# Step 7: Add firewall rules for NAT routing and allow routed traffic in UFW
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$INTERFACE" -j MASQUERADE
iptables-save > /etc/iptables/rules.v4

# Allow routed traffic in UFW
ufw allow in on tun0
ufw allow out on "$INTERFACE"

# Allow forwarding of routed traffic in UFW
echo "Allowing UFW routed traffic..."
ufw route allow in on tun0 out on "$INTERFACE"
ufw route allow in on "$INTERFACE" out on tun0
ufw reload

# Step 8: Create client configuration file
echo "Creating client configuration file..."
cat > "$OVPN_FILE" <<EOF
client
dev tun
proto tcp
remote $SERVER_IP 443
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
key-direction 1
<ca>
$(cat $EASYRSA_DIR/pki/ca.crt)
</ca>
<cert>
$(cat $EASYRSA_DIR/pki/issued/client.crt)
</cert>
<key>
$(cat $EASYRSA_DIR/pki/private/client.key)
</key>
<tls-auth>
$(cat $EASYRSA_DIR/pki/ta.key)
</tls-auth>
EOF

# Step 9: Restart OpenVPN service
echo "Restarting OpenVPN service..."
systemctl daemon-reload
systemctl restart openvpn@server.service
systemctl enable openvpn@server.service

# Step 10: Provide the SCP command to download the OVPN file
CLIENT_OVPN_NAME=$(basename "$OVPN_FILE")
echo "OpenVPN server setup complete. The client configuration file has been saved to $OVPN_FILE."
echo "To download the configuration file, use the following scp command:"
echo "scp $ORIGINAL_USER@${SERVER_IP}:$OVPN_FILE ~/Downloads/"

# End of script
