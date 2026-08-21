# QA-18: go.sum is CI-regenerated and intentionally not committed.
# `make bootstrap` (or ./bootstrap.sh) must run once after a clean clone.

.PHONY: bootstrap build test vet

bootstrap:
	go mod tidy

build: bootstrap
	go build ./...

vet: bootstrap
	go vet ./...

test: bootstrap
	go test ./...
