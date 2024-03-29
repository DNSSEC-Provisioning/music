CERTDIR:=etc/certs

all:
	@if [ ! -e ${CERTDIR}/RootCA.crt ] ; then make certs; fi
	$(MAKE) -C musicd
	$(MAKE) -C music-cli
	$(MAKE) -C scanner

fmt:
	gofmt -w `find common musicd music-cli -type f -name '*.go'`

certs:
	mkdir -p "${CERTDIR}"
	openssl req -x509 -nodes -new -sha256 -days 1024 -newkey rsa:2048 -keyout "${CERTDIR}/RootCA.key" -out "${CERTDIR}/RootCA.pem" -subj "/C=US/CN=Music-Root-CA"
	openssl x509 -outform pem -in "${CERTDIR}/RootCA.pem" -out "${CERTDIR}/RootCA.crt"
	openssl req -new -nodes -newkey rsa:2048 -keyout "${CERTDIR}/localhost.key" -out "${CERTDIR}/localhost.csr" -subj "/C=SE/ST=Confusion/L=Lost/O=Music-Certificates/CN=localhost.local"
	openssl x509 -req -sha256 -days 1024 -in "${CERTDIR}/localhost.csr" -CA "${CERTDIR}/RootCA.pem" -CAkey "${CERTDIR}/RootCA.key" -CAcreateserial -extfile domains.ext -out "${CERTDIR}/localhost.crt"

tar:
	cp musicd/musicd.yaml.sample etc/
	cp music-cli/music-cli.yaml.sample etc/
	cp scanner/scanner.yaml.sample etc/
	tar zcvf music-`uname -s`.tar.gz sbin etc/*.yaml.sample

tags:	*/*.go */*/*.go 
	/Applications/Aquamacs.app/Contents/MacOS/bin/etags */*.go */*/*.go > TAGS
