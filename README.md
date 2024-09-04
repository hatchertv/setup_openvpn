Key Features of the Script:
Automatically install OpenVPN and required dependencies.
Generate server and client certificates (using EasyRSA or OpenSSL).
Generate Diffie-Hellman parameters.
Create an OpenVPN server configuration file.
Enable IP forwarding and set up firewall rules.
Start the OpenVPN server.
Generate a client .ovpn file.
Provide SCP commands for the user to download the client config.


To deploy follow the following steps with a sudo enabled user:

git clone https://github.com/hatchertv/setup_openvpn.git

cd setup_openvpn/

sudo chmod +x setup_openvpn.sh

sudo ./setup_openvpn.sh

then follow onscreen instructions, enjoy!
