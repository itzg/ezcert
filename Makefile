DEP := ${GOPATH}/bin/dep
GORELEASER := ${GOPATH}/bin/goreleaser

default : release

test : vendor
	go test ./...

snapshot : vendor ${GORELEASER}
	${GORELEASER} --snapshot --skip-validate --rm-dist

release : vendor ${GORELEASER}
	${GORELEASER}

vendor : ${DEP}
	${DEP} ensure -vendor-only

${DEP} :
	go get -u github.com/golang/dep/cmd/dep

${GORELEASER} :
	go get github.com/goreleaser/goreleaser

.PHONY : default test snapshot release