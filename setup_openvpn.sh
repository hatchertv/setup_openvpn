#!/bin/bash

# This script sets up an OpenVPN server on any Linux machine, generates the necessary certificates, keys, and configuration files, and creates a client .ovpn file.

# Fail on any error
set -e

# Define variables
OVPN_DIR="/etc/openvpn"
EASYRSA_DIR="/etc/openvpn/easy-rsa"
KEY_DIR="/etc/openvpn/keys"
CLIENT_DIR="$HOME/client-configs"
CLIENT_NAME="client"
PORT=443
PROTO="tcp"

# Install OpenVPN and EasyRSA
install_openvpn() {
    echo "Installing OpenVPN and EasyRSA..."
    sudo apt-get update
    sudo apt-get install -y openvpn easy-rsa
}

# Generate server keys and certificates
generate_server_keys() {
    echo "Generating server keys and certificates..."

    # Setup EasyRSA
    make-cadir "$EASYRSA_DIR"
    cd "$EASYRSA_DIR"

    # Initialize the PKI, build CA and server certificate
    ./easyrsa init-pki
    ./easyrsa build-ca nopass
    ./easyrsa gen-req server nopass
    ./easyrsa sign-req server server

    # Generate Diffie-Hellman key
    ./easyrsa gen-dh

    # Generate TLS-Auth key for extra security
    openvpn --genkey --secret "$KEY_DIR/ta.key"

    # Copy keys to OpenVPN directory
    cp pki/ca.crt pki/private/server.key pki/issued/server.crt "$KEY_DIR"
    cp pki/dh.pem "$KEY_DIR/dh.pem"
}

# Generate client certificates
generate_client_keys() {
    echo "Generating client keys..."

    cd "$EASYRSA_DIR"
    ./easyrsa gen-req "$CLIENT_NAME" nopass
    ./easyrsa sign-req client "$CLIENT_NAME"

    # Copy client keys to client-configs directory
    mkdir -p "$CLIENT_DIR"
    cp pki/ca.crt pki/issued/"$CLIENT_NAME.crt" pki/private/"$CLIENT_NAME.key" "$CLIENT_DIR"
}

# Configure OpenVPN server
configure_server() {
    echo "Configuring OpenVPN server..."

    # Create server.conf
    cat <<EOF > "$OVPN_DIR/server.conf"
port $PORT
proto $PROTO
dev tun
ca $KEY_DIR/ca.crt
cert $KEY_DIR/server.crt
key $KEY_DIR/server.key
dh $KEY_DIR/dh.pem
tls-auth $KEY_DIR/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist $OVPN_DIR/ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status $OVPN_DIR/openvpn-status.log
log-append $OVPN_DIR/openvpn.log
verb 3
EOF
}

# Enable IP forwarding and configure firewall
setup_firewall() {
    echo "Setting up firewall and IP forwarding..."

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sed -i '/net.ipv4.ip_forward/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
    sysctl -p

    # Configure iptables
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
    iptables-save > /etc/iptables/rules.v4
}

# Create client configuration file
create_client_config() {
    echo "Creating client configuration file..."

    cat <<EOF > "$CLIENT_DIR/$CLIENT_NAME.ovpn"
client
dev tun
proto $PROTO
remote $(curl -s ifconfig.me) $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
key-direction 1
auth SHA256
<ca>
$(cat "$CLIENT_DIR/ca.crt")
</ca>
<cert>
$(cat "$CLIENT_DIR/$CLIENT_NAME.crt")
</cert>
<key>
$(cat "$CLIENT_DIR/$CLIENT_NAME.key")
</key>
<tls-auth>
$(cat "$KEY_DIR/ta.key")
</tls-auth>
EOF
}

# Start OpenVPN server
start_openvpn_server() {
    echo "Starting OpenVPN server..."
    systemctl start openvpn@server
    systemctl enable openvpn@server
}

# Output instructions
output_instructions() {
    echo "OpenVPN server setup complete."
    echo "Client configuration file is located at $CLIENT_DIR/$CLIENT_NAME.ovpn."
    echo "To download the client configuration file, use the following command:"
    echo "scp $USER@$(curl -s ifconfig.me):$CLIENT_DIR/$CLIENT_NAME.ovpn ~/Downloads"
}

# Main function
main() {
    install_openvpn
    generate_server_keys
    generate_client_keys
    configure_server
    setup_firewall
    create_client_config
    start_openvpn_server
    output_instructions
}

# Run the script
main
