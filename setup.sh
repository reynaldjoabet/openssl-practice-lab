O=/opt/homebrew/bin/openssl          # OpenSSL 4.0.2 — LibreSSL 3.3.6 at /usr/bin lacks -trace

# CA with an RSA key
$O req -x509 -newkey rsa:2048 -noenc -keyout ca.key -out ca.crt -days 3650 \
   -subj "/C=US/O=Abiding In Christ/CN=Abiding In Christ Root CA" \
   -addext "basicConstraints=critical,CA:TRUE" \
   -addext "keyUsage=critical,keyCertSign,cRLSign"

# Server with an EC key — deliberately a different algorithm family
$O ecparam -name prime256v1 -genkey -noout -out server.key
$O req -new -key server.key -out server.csr \
   -subj "/C=US/O=Abiding In Christ/CN=abidinginchrist.com"

$O x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
   -out server.crt -days 365 -sha256 \
   -extfile <(printf "subjectAltName=DNS:abidinginchrist.com,DNS:www.abidinginchrist.com\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
