#!/usr/bin/env bash

sudo dnf install -y epel-release
sudo dnf install -y openvpn

FIRST_INTERFACE=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | head -n 1)

EXTERNAL_IP="$(/sbin/ip -o -4 addr list $FIRST_INTERFACE | awk '{print $4}' | cut -d/ -f1)"

VALID_DAYS=3650

rm -rf /etc/pki/CA
mkdir /etc/pki/CA
mkdir /etc/pki/CA/private
mkdir /etc/pki/CA/certs
mkdir /etc/pki/CA/newcerts
cd /etc/pki/CA

touch index.txt
echo '01' > serial
echo '01' > crlnumber
mkdir req
chmod 600 req
cat > extensions.cnf <<EOL
[ server ]
basicConstraints=CA:FALSE
nsCertType=server
EOL

# New CA
openssl genrsa -out private/cakey.pem 2048
openssl req -x509 -new -key private/cakey.pem -days $VALID_DAYS -out cacert.pem -subj '/CN=ca_cox_lab/O=cloud/C=IL/ST=Herzliya/L=Herzliya'

# New server
## Request
openssl req -new -nodes -subj '/CN=server1/O=cloud/C=IL/ST=Herzliya/L=Herzliya' -keyout private/server.key -out req/server.req
## Sign
openssl ca -days $VALID_DAYS -batch -extfile extensions.cnf -extensions server -out certs/server.crt -infiles req/server.req

# New user
## Request
openssl req -new -nodes -subj '/CN=client1/O=cloud/C=IL/ST=Herzliya/L=Herzliya' -keyout private/client1.key -out req/client1.req
## Sign
openssl ca -days $VALID_DAYS -batch -out certs/client1.crt -infiles req/client1.req

# Copy files to openvpn folder

/bin/cp cacert.pem /etc/openvpn/server/ca.crt
/bin/cp private/server.key /etc/openvpn/server/server.key
/bin/cp certs/server.crt /etc/openvpn/server/server.crt
/bin/cp private/client1.key /etc/openvpn/server/client1.key
/bin/cp certs/client1.crt /etc/openvpn/server/client1.crt

# generate ta.key
openvpn --genkey --secret /etc/openvpn/server/ta.key
openssl dhparam -out /etc/openvpn/server/dh2048.pem 2048

cat > /etc/openvpn/server/server.conf <<EOL
port 1194
proto udp
dev tun

ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/server.crt
key /etc/openvpn/server/server.key  # This file should be kept secret
dh /etc/openvpn/server/dh2048.pem

server 10.8.0.0 255.255.255.0

# ifconfig-pool-persist ipp.txt

push "route 172.16.167.0 255.255.255.0"
push "route 172.16.168.0 255.255.255.0"

# DNS servers provided by opendns.com.
#push "dhcp-option DNS 192.168.0.1"

duplicate-cn

keepalive 10 120

tls-auth /etc/openvpn/server/ta.key 0 # This file is secret

comp-lzo

max-clients 10

user nobody
group nobody

persist-key
persist-tun

status /tmp/openvpn-status.log

log        /tmp/openvpn.log
log-append  /tmp/openvpn.log

verb 3

mute 20

#tun-mtu-extra 32
#tun-mtu 1460
#mssfix 1420
#reneg-sec 0
EOL

# Generate client 

tls_auth=$(cat /etc/openvpn/server/ta.key)
ca=$(cat /etc/openvpn/server/ca.crt)
cert=$(cat /etc/openvpn/server/client1.crt)
key=$(cat /etc/openvpn/server/client1.key)

cat > /etc/openvpn/client/client.ovpn << EOL
remote  $EXTERNAL_IP 1194
client
dev tun
proto udp
resolv-retry infinite
nobind
persist-key
persist-tun
ns-cert-type server
comp-lzo
verb 3

key-direction 1
<tls-auth>
$tls_auth
</tls-auth>

<ca>
$ca
</ca>
<cert>
$cert
</cert>
<key>
$key
</key>
EOL

systemctl daemon-reload
systemctl start openvpn-server@server.service
systemctl enable --now openvpn-server@server.service

echo "net.ipv4.ip_forward = 1" | tee -a /etc/sysctl.conf
sysctl --system

dnf install -y firewalld
systemctl start firewalld
systemctl enable firewalld
firewall-cmd --permanent --zone=public --add-port=1194/udp
firewall-cmd --reload
firewall-cmd --add-service openvpn --permanent
firewall-cmd --zone=public --permanent --add-masquerade
firewall-cmd --permanent --new-zone=openvpn
firewall-cmd --reload
firewall-cmd --zone=openvpn --permanent --add-forward-port=toaddr=172.16.167.0/24
firewall-cmd --zone=openvpn --permanent --add-forward-port=toaddr=172.16.168.0/24


firewall-cmd --zone=trusted --add-interface=tun0 --permanent
firewall-cmd --reload
firewall-cmd --permanent --zone=trusted --add-masquerade
DEV=$(ip route get 8.8.8.8 | awk 'NR==1 {print $(NF-2)}')
firewall-cmd --permanent --direct --passthrough ipv4 -t nat -A POSTROUTING -s  10.8.0.0/24 -o $DEV -j MASQUERADE
firewall-cmd --reload
