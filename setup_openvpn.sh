#!/bin/bash

# Stop and disable the OpenVPN service if running
sudo systemctl stop openvpn@server
sudo systemctl disable openvpn@server

# Clean up any existing OpenVPN configurations
sudo rm -rf /etc/openvpn
sudo rm -rf /var/log/openvpn*

# Reinstall OpenVPN to ensure a clean installation
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

# Calculate the optimal MTU for the server
MTU=$(ping -c 1 -M do -s 1432 google.com 2>/dev/null | grep -oP '(?<=MTU\s)\d+')
if [ -z "$MTU" ]; then
    MTU=1400  # Fallback MTU if the calculation fails
fi

# Create the server configuration file
cat << EOF | sudo tee /etc/openvpn/server.conf
port 443
proto tcp
dev tun
topology subnet
local $(curl -s http://checkip.amazonaws.com)  # Automatically determine the public IP address
ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
server 10.8.0.0 255.255.255.0
mtu $MTU
mssfix $((MTU-40))
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
push "mtu $MTU"
push "mssfix $((MTU-40))"
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

# Configure IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
sudo sed -i '/net.ipv4.ip_forward/c\net.ipv4.ip_forward=1' /etc/sysctl.conf
sudo sysctl -p

# Set up firewall rules
sudo ufw allow 443/tcp
sudo ufw allow OpenSSH
sudo ufw disable
sudo ufw enable

# Start and enable the OpenVPN service
sudo systemctl start openvpn@server
if [ $? -ne 0 ]; then
    echo "Error starting OpenVPN service"
    exit 1
fi
sudo systemctl enable openvpn@server

# Set the home directory for the client.ovpn file based on the user running the script
USER_HOME=$(eval echo ~${SUDO_USER})
CLIENT_CONFIG_PATH="${USER_HOME}/$(hostname -s)_client.ovpn"

# Generate the client configuration file
cat << EOF > ${CLIENT_CONFIG_PATH}
client
dev tun
proto tcp
remote $(curl -s http://checkip.amazonaws.com) 443
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
tun-mtu $MTU
mssfix $((MTU-40))
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

# Print out the location of the client configuration file and SCP command
echo "OpenVPN server setup complete. The client configuration file is available as ${CLIENT_CONFIG_PATH}."
echo "You can download it using the following SCP command:"
echo "scp ${USER}@$(curl -s http://checkip.amazonaws.com):${CLIENT_CONFIG_PATH} ."
