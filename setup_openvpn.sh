#!/bin/bash

# Function to get the primary IPv4 address using net-tools
get_public_ipv4() {
    IPV4_ADDRESS=$(ifconfig $(ip -4 route | grep default | awk '{print $5}') | grep 'inet ' | awk '{print $2}')
    if [ -z "$IPV4_ADDRESS" ]; then
        echo "Failed to obtain public IPv4 address. Exiting."
        exit 1
    else
        echo "Public IPv4 address is $IPV4_ADDRESS."
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

# Function to clean up previous OpenVPN configurations
cleanup_openvpn() {
    sudo systemctl stop openvpn@server-ipv4
    sudo systemctl disable openvpn@server-ipv4
    sudo rm -rf /etc/openvpn
    sudo rm -rf /var/log/openvpn*
}

# Function to reinstall OpenVPN
install_openvpn() {
    sudo apt-get update
    sudo apt-get install -y openvpn easy-rsa net-tools
}

# Function to set up the PKI and generate keys
setup_pki() {
    sudo mkdir -p /etc/openvpn
    sudo cp -r /usr/share/easy-rsa /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa

    sudo ./easyrsa init-pki
    sudo ./easyrsa --batch build-ca nopass
    sudo ./easyrsa build-server-full server nopass
    sudo ./easyrsa gen-dh
    sudo openvpn --genkey --secret /etc/openvpn/ta.key
    sudo ./easyrsa build-client-full client1 nopass

    sudo cp pki/ca.crt pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/
}

# Function to configure IP forwarding
configure_ip_forwarding() {
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
    sudo sed -i '/net.ipv4.ip_forward/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
    sudo sysctl -p
}

# Function to configure the firewall
configure_firewall() {
    sudo ufw allow 443/tcp
    sudo ufw allow OpenSSH
    sudo ufw disable
    sudo ufw enable
    sudo ufw allow routed
}

# Function to generate the client configuration file
generate_client_config() {
    USER_HOME=$(eval echo ~${SUDO_USER})
    SERVER_NAME=${IPV4_ADDRESS//./-}
    CLIENT_CONFIG_PATH="${USER_HOME}/client-${SERVER_NAME}-ipv4.ovpn"

    cat << EOF > ${CLIENT_CONFIG_PATH}
client
dev tun
proto tcp
remote ${IPV4_ADDRESS} 443
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
}

# Main script execution
cleanup_openvpn
install_openvpn
setup_pki
get_public_ipv4
configure_openvpn_ipv4
configure_ip_forwarding
configure_firewall
sudo systemctl start openvpn@server-ipv4
sudo systemctl enable openvpn@server-ipv4
generate_client_config

# Print out the location of the client configuration file and scp command
echo "OpenVPN server setup complete. The client configuration file is available as ${CLIENT_CONFIG_PATH}."
echo "To download the configuration file, use the following scp command:"
echo "scp ${SUDO_USER}@${IPV4_ADDRESS}:${CLIENT_CONFIG_PATH} ~/Downloads"
