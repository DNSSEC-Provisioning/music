PROG:=../sbin/music-cli
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

install:
	@mkdir -p ../etc ../sbin
#	install -s -b ${PROG} ../sbin/
	if [ ! -e ../etc/${CONFIG} ] ; then install -c ${CONFIG}.sample ../etc/${CONFIG}; fi

test:
	$(GO) test -v -cover

clean:
	@rm -f $(PROG)

.PHONY: build clean


