CERTDIR:=etc/certs

all:
	$(MAKE) -C musicd
	$(MAKE) -C music-cli

fmt:
	gofmt -w `find common musicd music-cli -type f -name '*.go'`
	gsed -i -e 's%	%    %g' `find common musicd music-cli -type f -name '*.go'`

cert:
	openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout ${CERTDIR}/RootCA.key -out ${CERTDIR}/RootCA.pem -subj "/C=US/CN=Music-Root-CA"
	openssl x509 -outform pem -in ${CERTDIR}/RootCA.pem -out ${CERTDIR}/RootCA.crt
	openssl req -new -nodes -newkey rsa:2048 -keyout ${CERTDIR}/localhost.key -out ${CERTDIR}/localhost.csr -subj "/C=SE/ST=Confusion/L=Lost/O=Music-Certificates/CN=localhost.local"
	openssl x509 -req -sha256 -days 1024  -in ${CERTDIR}/localhost.csr -CA ${CERTDIR}/RootCA.pem -CAkey ${CERTDIR}/RootCA.key -CAcreateserial -extfile domains.ext -out ${CERTDIR}/localhost.crt
