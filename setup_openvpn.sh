#!/bin/bash

# Function to determine the primary network interface
determine_primary_interface() {
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}')
    if [ -z "$PRIMARY_INTERFACE" ]; then
        echo "Error: Unable to determine the primary network interface."
        exit 1
    else
        echo "Primary Network Interface: $PRIMARY_INTERFACE"
    fi
}

# Function to configure OpenVPN server
configure_openvpn_server() {
    # Get the MTU from the primary interface
    PRIMARY_MTU=$(ifconfig $PRIMARY_INTERFACE | grep -i mtu | awk '{print $4}')
    VPN_MTU=$((PRIMARY_MTU - 50))

    echo "Primary MTU: $PRIMARY_MTU"
    echo "VPN MTU: $VPN_MTU"

    # Create the OpenVPN server configuration file
    cat << EOF | sudo tee /etc/openvpn/server.conf
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
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 6
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
verify-client-cert none
username-as-common-name
EOF
}

# Function to configure IP forwarding and NAT
configure_routing() {
    echo "Enabling IP forwarding..."
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
    sudo sed -i '/net.ipv4.ip_forward/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
    sudo sysctl -p

    echo "Configuring firewall rules..."
    sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $PRIMARY_INTERFACE -j MASQUERADE
    sudo iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A FORWARD -s 10.8.0.0/24 -j ACCEPT

    # Save the iptables rules
    sudo apt-get install -y iptables-persistent
    sudo netfilter-persistent save
}

# Function to install and configure OpenVPN
install_openvpn() {
    # Stop and disable OpenVPN if it's running
    sudo systemctl stop openvpn@server
    sudo systemctl disable openvpn@server

    # Clean up any existing OpenVPN configuration
    sudo rm -rf /etc/openvpn
    sudo rm -rf /var/log/openvpn*

    # Install OpenVPN and Easy-RSA
    sudo apt-get update
    sudo apt-get install -y openvpn easy-rsa

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

    # Generate Diffie-Hellman parameters
    sudo ./easyrsa gen-dh

    # Generate a shared TLS key for HMAC authentication
    sudo openvpn --genkey --secret /etc/openvpn/ta.key

    # Generate client certificate and key
    sudo ./easyrsa build-client-full client1 nopass

    # Move generated keys and certificates to the OpenVPN directory
    sudo cp pki/ca.crt pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/

    # Configure OpenVPN server
    configure_openvpn_server

    # Configure routing
    configure_routing

    # Enable and start the OpenVPN service
    sudo systemctl start openvpn@server
    sudo systemctl enable openvpn@server
}

# Function to create the client config file
create_client_config() {
    USER_HOME=$(eval echo ~${SUDO_USER})
    PUBLIC_IP=$(curl -s ifconfig.me)
    CLIENT_CONFIG_PATH="${USER_HOME}/client-${PUBLIC_IP//./-}-ipv4.ovpn"

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

    # Print out the location of the client configuration file
    echo "OpenVPN server setup complete. The client configuration file is available as ${CLIENT_CONFIG_PATH}."
    echo "To download the configuration file, use the following scp command:"
    echo "scp ${SUDO_USER}@${PUBLIC_IP}:${CLIENT_CONFIG_PATH} ."
}

# Main function
main() {
    # Determine the primary network interface
    determine_primary_interface

    # Install and configure OpenVPN
    install_openvpn

    # Create the client configuration file
    create_client_config
}

# Execute main function
main
