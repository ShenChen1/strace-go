#!/bin/bash
set -e

echo "==> [1/3] Cleaning previous build artifacts..."
sudo rm -f strace-go cmd/strace-go/bpf_bpf*.go cmd/strace-go/bpf_bpf*.o pkg/meta/syscall_table.go pkg/meta/xlat_auto.go

echo "==> [2/3] Generating Syscall Table and eBPF bytecode..."
echo "    (sudo is required to read /sys/kernel/tracing and parse events)"
cd cmd/strace-go
sudo go generate ./...
cd ../..

echo "==> [3/3] Building strace-go binary..."
go build -o strace-go ./cmd/strace-go

echo "==> Build complete! Successfully created 'strace-go' executable."
echo "    Run it with: sudo ./strace-go <command>"
