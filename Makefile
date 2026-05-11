APP=twag
BIN_DIR=bin
CMD=./cmd/twag
GOCACHE?=/tmp/vectorcore-twag-gocache
GOMODCACHE?=/tmp/vectorcore-twag-gomodcache
GOENV=GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE)
VERSION?=dev
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE?=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: build tidy test clean install

build:
	$(GOENV) go build -buildvcs=false -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(APP) $(CMD)

tidy:
	$(GOENV) go mod tidy

test:
	$(GOENV) go test ./...

clean:
	rm -rf $(BIN_DIR)

install: build
	install -d /opt/vectorcore/twag/bin
	install -d /etc/vectorcore/twag
	install -d /var/log/vectorcore/twag
	install -m 0755 $(BIN_DIR)/$(APP) /opt/vectorcore/twag/bin/$(APP)
