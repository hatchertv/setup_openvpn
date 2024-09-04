#!/bin/bash

# Define variables
VPN_PORT=${VPN_PORT:-443}
VPN_PROTOCOL=${VPN_PROTOCOL:-tcp}
VPN_CIPHER=${VPN_CIPHER:-AES-256-GCM}
VPN_MTU=${VPN_MTU:-1500}
VPN_SUBNET="10.8.0.0/24"
VPN_INTERFACE="tun0"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
CLIENT_NAME="client"

# Check if OpenVPN is installed
if ! command -v openvpn &> /dev/null; then
    echo "Installing OpenVPN..."
    sudo apt-get update && sudo apt-get install -y openvpn easy-rsa
else
    echo "OpenVPN and EasyRSA are already installed."
fi

# Ensure port is available (e.g., 443)
check_port_in_use() {
    if lsof -i :$VPN_PORT &> /dev/null; then
        echo "Port $VPN_PORT is in use, stopping conflicting service..."
        PID=$(lsof -ti :$VPN_PORT)
        kill $PID
    fi
}

check_port_in_use

# Clean up previous configurations
clean_old_config() {
    echo "Cleaning up old VPN configurations..."
    sudo rm -rf /etc/openvpn/server.conf
    sudo rm -rf /etc/openvpn/*.log
}

clean_old_config

# Enable IP forwarding
enable_ip_forwarding() {
    echo "Enabling IP forwarding..."
    sudo sysctl -w net.ipv4.ip_forward=1
    sudo sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
    echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
}

enable_ip_forwarding

# Set up firewall rules
configure_firewall() {
    echo "Configuring firewall..."
    sudo iptables -F
    sudo iptables -t nat -F
    sudo iptables -t nat -A POSTROUTING -s $VPN_SUBNET -o enp1s0 -j MASQUERADE
    sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A FORWARD -s $VPN_SUBNET -o enp1s0 -j ACCEPT
    sudo iptables -A FORWARD -o $VPN_INTERFACE -i enp1s0 -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables-save | sudo tee /etc/iptables/rules.v4
}

configure_firewall

# Create OpenVPN server config
create_server_config() {
    echo "Creating OpenVPN server configuration..."
    sudo tee /etc/openvpn/server.conf > /dev/null <<EOL
port $VPN_PORT
proto $VPN_PROTOCOL
dev $VPN_INTERFACE
tun-mtu $VPN_MTU
topology subnet
server 10.8.0.0 255.255.255.0
keepalive 10 120
persist-key
persist-tun
user nobody
group nogroup
cipher $VPN_CIPHER
data-ciphers AES-256-GCM:AES-128-GCM
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 3
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
verify-client-cert none
username-as-common-name
client-to-client
push "redirect-gateway def1"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
EOL
}

create_server_config

# Set up CA, keys, and certificates (with EasyRSA)
setup_certificates() {
    echo "Setting up certificates with EasyRSA..."
    
    # Install EasyRSA if not already installed
    if [ ! -d "$EASYRSA_DIR" ]; then
        sudo mkdir -p "$EASYRSA_DIR"
        sudo ln -s /usr/share/easy-rsa/* "$EASYRSA_DIR/"
    fi

    # Initialize the PKI
    cd $EASYRSA_DIR
    sudo ./easyrsa init-pki

    # Build CA
    sudo ./easyrsa build-ca nopass <<EOF
MyOpenVPNCA
EOF

    # Create server key and certificate
    sudo ./easyrsa gen-req server nopass
    sudo ./easyrsa sign-req server server <<EOF
yes
EOF

    # Generate Diffie-Hellman parameters
    sudo ./easyrsa gen-dh

    # Generate the TLS-Auth key (optional but recommended)
    sudo openvpn --genkey --secret ta.key

    # Move files to OpenVPN directory
    sudo cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key /etc/openvpn/
}

setup_certificates

# Generate client .ovpn file
generate_client_ovpn() {
    echo "Generating client .ovpn configuration..."

    # Create client key and certificate
    sudo ./easyrsa gen-req $CLIENT_NAME nopass
    sudo ./easyrsa sign-req client $CLIENT_NAME <<EOF
yes
EOF

    # Generate the client .ovpn file
    CLIENT_CONFIG="/home/$USER/${CLIENT_NAME}.ovpn"
    sudo tee $CLIENT_CONFIG > /dev/null <<EOL
client
dev tun
proto $VPN_PROTOCOL
remote $(curl -s ifconfig.me) $VPN_PORT
resolv-retry infinite
nobind
persist-key
persist-tun
cipher $VPN_CIPHER
data-ciphers AES-256-GCM:AES-128-GCM
verb 3
auth-user-pass

<ca>
$(sudo cat /etc/openvpn/ca.crt)
</ca>

<cert>
$(sudo cat pki/issued/${CLIENT_NAME}.crt)
</cert>

<key>
$(sudo cat pki/private/${CLIENT_NAME}.key)
</key>

key-direction 1
<tls-auth>
$(sudo cat /etc/openvpn/ta.key)
</tls-auth>
EOL

    echo "Client configuration file generated: $CLIENT_CONFIG"
}

generate_client_ovpn

# Restart OpenVPN
restart_openvpn() {
    echo "Restarting OpenVPN service..."
    sudo systemctl daemon-reload
    sudo systemctl restart openvpn@server
    sudo systemctl enable openvpn@server
}

restart_openvpn

# Final check if OpenVPN is running correctly
check_openvpn_status() {
    if systemctl is-active --quiet openvpn@server; then
        echo "OpenVPN is running successfully!"
    else
        echo "OpenVPN failed to start. Check logs."
        sudo journalctl -xeu openvpn@server
    fi
}

check_openvpn_status

# Provide SCP command to download client .ovpn
provide_scp_command() {
    IP_ADDRESS=$(curl -s ifconfig.me)
    echo "To download the client configuration file, use the following command:"
    echo "scp $USER@$IP_ADDRESS:/home/$USER/${CLIENT_NAME}.ovpn ~/Downloads"
}

provide_scp_command

echo "Setup complete."
