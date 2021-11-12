PROG:=../sbin/musicd
CONFIG:=musicd.yaml

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
	@mkdir -p ../etc ../sbin
	@touch ../etc/musicd.tokens.yaml
	@touch /var/tmp/music.db
#	install -s -b ${PROG} ../sbin/
	if [ ! -e ../etc/${CONFIG} ] ; then install -c ${CONFIG}.sample ../etc/${CONFIG}; fi

test:
	$(GO) test -v -cover

clean:
	@rm -f $(PROG)

.PHONY: build clean generate

