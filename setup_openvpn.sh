#!/bin/bash

# Function to check for IPv4 and IPv6 availability
check_ip_versions() {
    IPV4_AVAILABLE=$(ip -4 addr show | grep inet | wc -l)
    IPV6_AVAILABLE=$(ip -6 addr show | grep inet6 | wc -l)

    if [ "$IPV4_AVAILABLE" -gt 0 ]; then
        echo "IPv4 is available."
    else
        echo "IPv4 is not available."
    fi

    if [ "$IPV6_AVAILABLE" -gt 0 ]; then
        echo "IPv6 is available."
    else
        echo "IPv6 is not available."
    fi
}

# Function to prompt user for configuration options
prompt_user_for_config() {
    echo "Select your option for configuration:"
    echo "1. IPv4"
    echo "2. IPv6"
    echo "3. Both IPv4 and IPv6"
    read -p "Enter your choice (1/2/3): " CONFIG_CHOICE
}

# Function to configure OpenVPN based on user choice
configure_openvpn() {
    case $CONFIG_CHOICE in
        1)
            echo "Configuring OpenVPN for IPv4 only..."
            configure_openvpn_ipv4
            ;;
        2)
            echo "Configuring OpenVPN for IPv6 only..."
            configure_openvpn_ipv6
            ;;
        3)
            echo "Configuring OpenVPN for both IPv4 and IPv6..."
            configure_openvpn_ipv4
            configure_openvpn_ipv6
            ;;
        *)
            echo "Invalid choice. Please run the script again and select a valid option."
            exit 1
            ;;
    esac
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
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
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

# Function to configure OpenVPN for IPv6
configure_openvpn_ipv6() {
    # Determine the primary IPv6 interface and its MTU
    PRIMARY_INTERFACE=$(ip -6 route | grep default | awk '{print $5}')
    PRIMARY_MTU=$(ifconfig $PRIMARY_INTERFACE | grep -i mtu | awk '{print $4}')
    VPN_MTU=$((PRIMARY_MTU - 50))

    echo "Primary IPv6 Interface: $PRIMARY_INTERFACE"
    echo "Primary IPv6 MTU: $PRIMARY_MTU"
    echo "VPN IPv6 MTU: $VPN_MTU"

    # Create the server configuration file for IPv6
    cat << EOF | sudo tee /etc/openvpn/server-ipv6.conf
port 443
proto tcp6
dev tun
tun-mtu $VPN_MTU
topology subnet
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
server-ipv6 2001:db8::/64
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 2001:4860:4860::8888"
push "dhcp-option DNS 2001:4860:4860::8844"
keepalive 10 120
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status /var/log/openvpn-status-ipv6.log
log /var/log/openvpn-ipv6.log
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

# Check for IPv4 and IPv6 availability
check_ip_versions

# Prompt the user for configuration options
prompt_user_for_config

# Configure OpenVPN based on user choice
configure_openvpn

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
if [ "$CONFIG_CHOICE" == "1" ] || [ "$CONFIG_CHOICE" == "3" ]; then
    sudo systemctl start openvpn@server-ipv4
    sudo systemctl enable openvpn@server-ipv4
fi

if [ "$CONFIG_CHOICE" == "2" ] || [ "$CONFIG_CHOICE" == "3" ]; then
    sudo systemctl start openvpn@server-ipv6
    sudo systemctl enable openvpn@server-ipv6
fi

# Set the home directory for the client.ovpn file based on the user running the script
USER_HOME=$(eval echo ~${SUDO_USER})
PUBLIC_IP=$(curl -s ifconfig.me)
SERVER_NAME=${PUBLIC_IP//./-}
CLIENT_CONFIG_PATH_IPV4="${USER_HOME}/client-${SERVER_NAME}-ipv4.ovpn"
CLIENT_CONFIG_PATH_IPV6="${USER_HOME}/client-${SERVER_NAME}-ipv6.ovpn"

# Generate the client configuration file for IPv4
if [ "$CONFIG_CHOICE" == "1" ] || [ "$CONFIG_CHOICE" == "3" ]; then
    cat << EOF > ${CLIENT_CONFIG_PATH_IPV4}
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
fi

# Generate the client configuration file for IPv6
if [ "$CONFIG_CHOICE" == "2" ] || [ "$CONFIG_CHOICE" == "3" ]; then
    cat << EOF > ${CLIENT_CONFIG_PATH_IPV6}
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
fi

# Print out the location of the client configuration file and scp command
if [ "$CONFIG_CHOICE" == "1" ] || [ "$CONFIG_CHOICE" == "3" ]; then
    echo "OpenVPN server setup complete. The client configuration file is available as ${CLIENT_CONFIG_PATH_IPV4}."
    echo "To download the configuration file, use the following scp command:"
    echo "scp ${SUDO_USER}@${PUBLIC_IP}:${CLIENT_CONFIG_PATH_IPV4} ."
fi

if [ "$CONFIG_CHOICE" == "2" ] || [ "$CONFIG_CHOICE" == "3" ]; then
    echo "OpenVPN server setup complete. The client configuration file is available as ${CLIENT_CONFIG_PATH_IPV6}."
    echo "To download the configuration file, use the following scp command:"
    echo "scp ${SUDO_USER}@${PUBLIC_IP}:${CLIENT_CONFIG_PATH_IPV6} ."
fi
