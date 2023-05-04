PROG:=music-cli
CONFIG:=music-cli.yaml
COMMIT:=$(shell git describe --dirty=+WiP --always)
VERSION=$(shell cat ./VERSION)

GOFLAGS:=-ldflags "-X app.version=$(VERSION)-$(COMMIT) -v"

GOOS ?= $(shell uname -s | tr A-Z a-z)
# amd64:
# GOARCH:=amd64
# rpi3:
# GOARCH:=arm64
# rpi2:
# GOARCH:=arm

GO:=GOOS=$(GOOS) CGO_ENABLED=0 go

default: ${PROG}

${PROG}: build

arm:
	GOARCH=arm $(GO) build $(GOFLAGS) -o ${PROG}

arm64:
	GOARCH=arm64 $(GO) build $(GOFLAGS) -o ${PROG}

build:
	GOARCH=amd64 $(GO) build $(GOFLAGS) -o ${PROG}

install-local:
	@mkdir -p /etc/music/conf /usr/local/bin
	install ${PROG} /usr/local/bin/
	if [ ! -e /etc/music/conf/${CONFIG} ] ; then install -c ${CONFIG}.local /etc/music/conf/${CONFIG}; fi

install-docker:
	@mkdir -p /etc/music/conf /usr/local/bin
	install ${PROG} /usr/local/bin
	if [ ! -e /etc/music/conf/${CONFIG} ] ; then install -c ${CONFIG}.docker /etc/music/conf/${CONFIG}; fi

test:
	$(GO) test -v -cover

clean:
	@rm -f $(PROG)

.PHONY: build clean


