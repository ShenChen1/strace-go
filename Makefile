ARCH ?= $(shell go env GOARCH)
HOST_GOARCH := $(shell go env GOHOSTARCH)
HOST_GOOS := $(shell go env GOHOSTOS)
GO_TEST_EXEC ?=

ifeq ($(ARCH),amd64)
else ifeq ($(ARCH),arm64)
else
$(error unsupported architecture: $(ARCH); supported architectures: amd64, arm64)
endif

.PHONY: build test generate-bpf generate-metadata check-metadata
build: generate-bpf
	GOOS=linux GOARCH="$(ARCH)" go build -o strace-go ./cmd/strace-go

test:
	GOOS=linux GOARCH="$(ARCH)" go test $(if $(GO_TEST_EXEC),-exec "$(GO_TEST_EXEC)") ./...

generate-bpf:
	./scripts/generate-bpf.sh "$(ARCH)"

generate-metadata:
	GOOS="$(HOST_GOOS)" GOARCH="$(HOST_GOARCH)" go run ./cmd/generate-syscalls -arch all

check-metadata:
	GOOS="$(HOST_GOOS)" GOARCH="$(HOST_GOARCH)" go run ./cmd/generate-syscalls -arch all -check
