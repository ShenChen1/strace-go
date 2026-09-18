ARCH ?= $(shell go env GOARCH)
HOST_GOARCH := $(shell go env GOHOSTARCH)
HOST_GOOS := $(shell go env GOHOSTOS)

ifeq ($(ARCH),amd64)
else ifeq ($(ARCH),arm64)
else
$(error unsupported architecture: $(ARCH); supported architectures: amd64, arm64)
endif

.PHONY: build test generate-bpf generate-metadata check-metadata
build: generate-bpf
	GOOS=linux GOARCH="$(ARCH)" go build -o strace-go ./cmd/strace-go

NATIVE_TEST_ERROR :=
ifneq ($(strip $(GO_TEST_EXEC)),)
NATIVE_TEST_ERROR := GO_TEST_EXEC is disabled; tests must run on the matching native host
else ifneq ($(HOST_GOOS),linux)
NATIVE_TEST_ERROR := native tests require a Linux host; current host is $(HOST_GOOS)/$(HOST_GOARCH)
else ifneq ($(HOST_GOARCH),$(ARCH))
NATIVE_TEST_ERROR := native tests require a native Linux/$(ARCH) host; current host is $(HOST_GOOS)/$(HOST_GOARCH)
endif

test:
ifneq ($(strip $(NATIVE_TEST_ERROR)),)
	$(error $(NATIVE_TEST_ERROR))
else
	GOOS=linux GOARCH="$(ARCH)" go test ./...
endif

generate-bpf:
	./scripts/generate-bpf.sh "$(ARCH)"

generate-metadata:
	GOOS="$(HOST_GOOS)" GOARCH="$(HOST_GOARCH)" go run ./cmd/generate-syscalls -arch all

check-metadata:
	GOOS="$(HOST_GOOS)" GOARCH="$(HOST_GOARCH)" go run ./cmd/generate-syscalls -arch all -check
