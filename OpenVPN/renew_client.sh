#!/bin/bash

VALID_DAYS=3650



cd /etc/pki/CA
rm -f index.txt
rm -f serial
rm -f crlnumber
rm -fr req

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

/bin/cp cacert.pem /etc/openvpn/ca.crt
/bin/cp private/server.key /etc/openvpn/server.key
/bin/cp certs/server.crt /etc/openvpn/server.crt
/bin/cp private/client1.key /etc/openvpn/client1.key
/bin/cp certs/client1.crt /etc/openvpn/client1.crt
systemctl restart openvpn@server

# Generate client.ovpn file

publicip="$(/sbin/ip -o -4 addr list eno16780032 | awk '{print $4}' | cut -d/ -f1)"
tls_auth=$(cat /etc/openvpn/ta.key)
ca=$(cat /etc/openvpn/ca.crt)
cert=$(cat /etc/openvpn/client1.crt)
key=$(cat /etc/openvpn/client1.key)

cat > /etc/openvpn/client.ovpn <<EOL
remote  $publicip 1194
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

