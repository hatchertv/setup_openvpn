#!/bin/bash

# Function to check for IPv4 availability
check_ip_versions() {
    IPV4_AVAILABLE=$(ip -4 addr show | grep inet | wc -l)

    if [ "$IPV4_AVAILABLE" -gt 0 ]; then
        echo "IPv4 is available."
    else
        echo "IPv4 is not available."
        exit 1
    fi
}

# Function to configure OpenVPN for IPv4
configure_openvpn_ipv4() {
    # Determine the primary IPv4 interface and its MTU
    PRIMARY_INTERFACE=$(ip -4 route | grep default | awk '{print $5}')
    PRIMARY_MTU=$(ifconfig $PRIMARY_INTERFACE | grep -i mtu | awk '{print $4}')
    VPN_MTU=$((PRIMARY_MTU - 50))

    echo "Primary IPv4 Interface: $PRIMARY_INTERFACE"
    echo "Primary IPv4 MTU: $PRIMARY_MTU"
    echo "VPN IPv4 MTU: $VPN_MTU"

    # Create the server configuration file for IPv4
    cat << EOF | sudo tee /etc/openvpn/server-ipv4.conf
port 443
proto tcp
dev tun
tun-mtu $VPN_MTU
topology subnet
ca /etc/openvpn/ca.crt
cert /etc/openvpn/server.crt
key /etc/openvpn/server.key
dh /etc/openvpn/dh.pem
tls-auth /etc/openvpn/ta.key 0
server 10.8.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn-status-ipv4.log
log /var/log/openvpn-ipv4.log
verb 6
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
verify-client-cert none
username-as-common-name
EOF
}

# Stop and disable the OpenVPN service if running
sudo systemctl stop openvpn@server
sudo systemctl disable openvpn@server

# Clean up any existing OpenVPN configurations
sudo rm -rf /etc/openvpn
sudo rm -rf /var/log/openvpn*

# Reinstall OpenVPN and install necessary tools
sudo apt-get update
sudo apt-get install -y openvpn easy-rsa net-tools

# Set up the OpenVPN server configuration directory
sudo mkdir -p /etc/openvpn
sudo cp -r /usr/share/easy-rsa /etc/openvpn/easy-rsa
cd /etc/openvpn/easy-rsa

# Initialize the PKI (Public Key Infrastructure)
sudo ./easyrsa init-pki

# Build the Certificate Authority (CA)
sudo ./easyrsa --batch build-ca nopass

# Generate the server certificate and key
sudo ./easyrsa build-server-full server nopass
if [ $? -ne 0 ]; then
    echo "Error generating server certificate and key"
    exit 1
fi

# Generate Diffie-Hellman parameters
sudo ./easyrsa gen-dh
if [ $? -ne 0 ]; then
    echo "Error generating Diffie-Hellman parameters"
    exit 1
fi

# Generate a shared TLS key for HMAC authentication
sudo openvpn --genkey --secret /etc/openvpn/ta.key
if [ $? -ne 0 ]; then
    echo "Error generating TLS key"
    exit 1
fi

# Generate client certificate and key
sudo ./easyrsa build-client-full client1 nopass
if [ $? -ne 0 ]; then
    echo "Error generating client certificate and key"
    exit 1
fi

# Move generated keys and certificates to the OpenVPN directory
sudo cp pki/ca.crt pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/

# Check for IPv4 availability
check_ip_versions

# Configure OpenVPN for IPv4 only
configure_openvpn_ipv4

# Configure IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo sed -i '/net.ipv4.ip_forward/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
sudo sysctl -p

# Set up firewall rules
sudo ufw allow 443/tcp
sudo ufw allow OpenSSH
sudo ufw disable
sudo ufw enable
sudo ufw allow routed

# Start and enable the OpenVPN service
sudo systemctl start openvpn@server-ipv4
if [ $? -ne 0 ]; then
    echo "Error starting OpenVPN service"
    exit 1
fi
sudo systemctl enable openvpn@server-ipv4

# Set the home directory for the client.ovpn file based on the user running the script
USER_HOME=$(eval echo ~${SUDO_USER})
PUBLIC_IP=$(curl -s ifconfig.me)
SERVER_NAME=${PUBLIC_IP//./-}
CLIENT_CONFIG_PATH="${USER_HOME}/client-${SERVER_NAME}-ipv4.ovpn"

# Generate the client configuration file
cat << EOF > ${CLIENT_CONFIG_PATH}
client
dev tun
proto tcp
remote ${PUBLIC_IP} 443
resolv-retry infinite
nobind
user nobody
group nogroup
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
cipher AES-256-CBC
verb 3
tun-mtu $VPN_MTU
<ca>
$(sudo cat /etc/openvpn/ca.crt)
</ca>
<cert>
$(sudo cat /etc/openvpn/easy-rsa/pki/issued/client1.crt)
</cert>
<key>
$(sudo cat /etc/openvpn/easy-rsa/pki/private/client1.key)
</key>
<tls-auth>
$(sudo cat /etc/openvpn/ta.key)
</tls-auth>
key-direction 1
EOF

# Print out the location of the client configuration file and scp command
echo "OpenVPN server setup complete. The client configuration file is available as ${CLIENT_CONFIG_PATH}."
echo "To download the configuration file, use the following scp command:"
echo "scp ${SUDO_USER}@${PUBLIC_IP}:${CLIENT_CONFIG_PATH} ~/Downloads"
