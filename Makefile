ARCH ?= $(shell go env GOARCH)
HOST_GOARCH := $(shell go env GOHOSTARCH)

.PHONY: build test generate-bpf generate-metadata check-metadata
build: generate-bpf
	GOOS=linux GOARCH=$(ARCH) go build -o strace-go ./cmd/strace-go

test:
	go test ./...

generate-bpf:
	./scripts/generate-bpf.sh $(ARCH)

generate-metadata:
	GOARCH=$(HOST_GOARCH) go run ./cmd/generate-syscalls -arch all

check-metadata:
	GOARCH=$(HOST_GOARCH) go run ./cmd/generate-syscalls -arch all -check
