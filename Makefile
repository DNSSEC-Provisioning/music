all:
	$(MAKE) -C musicd
	$(MAKE) -C music-cli

fmt:
	gofmt -w `find common musicd music-cli -type f -name '*.go'`
	sed -i -e 's%	%    %g' `find common musicd music-cli -type f -name '*.go'`
