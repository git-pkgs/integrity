.PHONY: test lint bench fuzz

test:
	go test -race ./...

lint:
	golangci-lint run --enable gocritic,gocognit,gocyclo,maintidx,dupl,mnd,unparam,ireturn,goconst,errcheck ./...
	govulncheck ./...
	deadcode ./...

bench:
	go test -run '^$$' -bench . -benchmem ./...

FUZZTIME ?= 30s
fuzz:
	go test -fuzz=FuzzParseSRI -fuzztime=$(FUZZTIME) .
	go test -fuzz=FuzzSRIRoundTrip -fuzztime=$(FUZZTIME) .
