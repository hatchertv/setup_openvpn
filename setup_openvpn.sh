#!/bin/bash

set -e

# Configuration parameters
SERVER_IP=$(curl -s http://checkip.amazonaws.com)
PORT=443
PROTOCOL="tcp"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
OVPN_FILE_DIR="/home/$USER"
CLIENT_NAME="client"

# Colors for output
GREEN="\033[0;32m"
RED="\033[0;31m"
NC="\033[0m"

echo -e "${GREEN}OpenVPN deployment script starting...${NC}"

# Check if the user is root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Install necessary packages
echo -e "${GREEN}Installing OpenVPN and EasyRSA...${NC}"
apt update && apt install -y openvpn easy-rsa iptables

# Set up the EasyRSA directory
if [ -d "$EASYRSA_DIR" ]; then
    echo "$EASYRSA_DIR already exists. Would you like to:
    1) Delete and recreate the EasyRSA directory (this will remove all existing keys/certs)
    2) Continue with the existing directory"

    read -p "Enter 1 or 2: " choice

    if [ "$choice" == "1" ]; then
        echo -e "${RED}Deleting and recreating EasyRSA directory...${NC}"
        rm -rf "$EASYRSA_DIR"
        make-cadir "$EASYRSA_DIR"
    elif [ "$choice" == "2" ]; then
        echo -e "${GREEN}Continuing with the existing EasyRSA directory...${NC}"
    else
        echo -e "${RED}Invalid choice. Exiting...${NC}"
        exit 1
    fi
else
    echo -e "${GREEN}Creating EasyRSA directory...${NC}"
    make-cadir "$EASYRSA_DIR"
fi

# Move to the EasyRSA directory
cd "$EASYRSA_DIR"
./easyrsa init-pki
./easyrsa build-ca nopass

echo -e "${GREEN}Generating server key and certificate...${NC}"
./easyrsa gen-req server nopass
./easyrsa sign-req server server

echo -e "${GREEN}Generating Diffie-Hellman parameters...${NC}"
./easyrsa gen-dh

echo -e "${GREEN}Generating client key and certificate...${NC}"
./easyrsa gen-req $CLIENT_NAME nopass
./easyrsa sign-req client $CLIENT_NAME

# Move certificates to OpenVPN directory
cp pki/ca.crt pki/issued/server.crt pki/private/server.key pki/dh.pem /etc/openvpn

# Generate TLS key for extra security
openvpn --genkey --secret /etc/openvpn/ta.key

# Create OpenVPN server configuration
cat > /etc/openvpn/server.conf << EOF
port $PORT
proto $PROTOCOL
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
keepalive 10 120
persist-key
persist-tun
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
EOF

# Enable IP forwarding and configure iptables
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i '/net.ipv4.ip_forward/s/^#//g' /etc/sysctl.conf

iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
iptables-save > /etc/iptables.rules

# Create a systemd service file
systemctl enable openvpn@server
systemctl start openvpn@server

# Create client configuration file
echo -e "${GREEN}Creating client configuration file...${NC}"
cat > "$OVPN_FILE_DIR/$CLIENT_NAME.ovpn" << EOF
client
dev tun
proto $PROTOCOL
remote $SERVER_IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
key-direction 1
verb 3
<ca>
$(cat "$EASYRSA_DIR/pki/ca.crt")
</ca>
<cert>
$(cat "$EASYRSA_DIR/pki/issued/$CLIENT_NAME.crt")
</cert>
<key>
$(cat "$EASYRSA_DIR/pki/private/$CLIENT_NAME.key")
</key>
<tls-auth>
$(cat /etc/openvpn/ta.key)
</tls-auth>
EOF

echo -e "${GREEN}Client configuration file created: $OVPN_FILE_DIR/$CLIENT_NAME.ovpn${NC}"

# Provide scp command for download
echo -e "${GREEN}To download the client configuration file, use:${NC}"
echo -e "${GREEN}scp $USER@$SERVER_IP:$OVPN_FILE_DIR/$CLIENT_NAME.ovpn ~/Downloads${NC}"

echo -e "${GREEN}OpenVPN server setup complete.${NC}"
