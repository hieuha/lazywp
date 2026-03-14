BINARY := lazywp
MODULE := github.com/hieuha/lazywp
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X $(MODULE)/internal/cli.Version=$(VERSION) -X $(MODULE)/internal/cli.Commit=$(COMMIT) -X $(MODULE)/internal/cli.Date=$(DATE)"

.PHONY: build test lint clean install vet

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/lazywp

test:
	go test ./... -v -count=1

test-coverage:
	go test ./... -coverprofile=cover.out
	go tool cover -html=cover.out -o cover.html

lint: vet
	@which staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

vet:
	go vet ./...

clean:
	rm -f $(BINARY) cover.out cover.html

install: build
	cp $(BINARY) $(GOPATH)/bin/ 2>/dev/null || cp $(BINARY) ~/go/bin/
