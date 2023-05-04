PROG:=musicd
CONFIG:=musicd.yaml
DB:=/var/tmp/music.db

VERSION:=$(shell git describe --dirty=+WiP --always)
GOFLAGS:=-v -ldflags "-X app.version=$(VERSION) -v"

GOOS ?= $(shell uname -s | tr A-Z a-z)
GOARCH:=amd64

# GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go
GO:=GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=1 go

default: ${PROG}

${PROG}: build

build:	
	$(GO) build $(GOFLAGS) -o ${PROG} 

install: ${PROG}
	@mkdir -p /etc/music/conf /etc/music/certs  /usr/local/bin
	@touch /etc/music/conf/musicd.tokens.yaml
	@touch ${DB}
	install ${PROG} /usr/local/bin
	if [ ! -e /etc/music/conf/${CONFIG} ] ; then install -c ${CONFIG}.sample /etc/music/conf/${CONFIG}; fi
	if [ ! -e /etc/music/certs/PublicRootCAs.pem ] ; then install -c PublicRootCAs.pem /etc/music/certs/; fi

test:
	$(GO) test -v -cover

clean:
	@rm -f $(PROG)

.PHONY: build clean generate

