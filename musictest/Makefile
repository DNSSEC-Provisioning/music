CERTDIR:=etc/certs
CONFDIR:=etc/conf

certs:
	mkdir -p "${CERTDIR}"
	openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout "${CERTDIR}/RootCA.key" -out "${CERTDIR}/RootCA.pem" -subj "/C=US/CN=Music-Root-CA"
	openssl x509 -outform pem -in "${CERTDIR}/RootCA.pem" -out "${CERTDIR}/RootCA.crt"
	openssl req -new -nodes -newkey rsa:2048 -keyout "${CERTDIR}/localhost.key" -out "${CERTDIR}/localhost.csr" -subj "/C=SE/ST=Confusion/L=Lost/O=Music-Certificates/CN=localhost.local"
	openssl x509 -req -sha256 -days 1024 -in "${CERTDIR}/localhost.csr" -CA "${CERTDIR}/RootCA.pem" -CAkey "${CERTDIR}/RootCA.key" -CAcreateserial -extfile domains.ext -out "${CERTDIR}/localhost.crt"


musicd-conf:
	mkdir -p ${CONFDIR}
	@touch ${CONFDIR}/musicd.tokens.yaml
	if [ ! -e ${CONFDIR}/musicd.yaml ]; then install -c ../musicd/musicd.yaml.sample ${CONFDIR}/musicd.yaml; fi
	if [ ! -e ${CERTDIR}/PublicRootCAs.pem ]; then install -c ../musicd/PublicRootCAs.pem ${CERTDIR}/PublicRootCAs.pem; fi
