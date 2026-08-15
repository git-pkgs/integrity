.PHONY: test lint bench fuzz

test:
	go test -race ./...

lint:
	golangci-lint run --enable gocritic,gocognit,gocyclo,maintidx,dupl,mnd,unparam,ireturn,goconst,errcheck ./...
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

FUZZTIME ?= 30s
fuzz:
	go test -fuzz=FuzzParseSRI -fuzztime=$(FUZZTIME) .
	go test -fuzz=FuzzSRIRoundTrip -fuzztime=$(FUZZTIME) .
