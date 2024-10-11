PROG:=sidecar-cli

GOFLAGS:=-ldflags "-X app.version=$(VERSION)-$(COMMIT) -v"
GO:=CGO_ENABLED=0 go

include ../utils/Makefile.common

install:
	@mkdir -p ../etc ../sbin
#	install -s -b ${PROG} ../sbin/
	if [ ! -e ../etc/${CONFIG} ] ; then install -c ${CONFIG}.sample ../etc/${CONFIG}; fi


