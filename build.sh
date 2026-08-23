#!/bin/bash
set -e

echo "==> [1/3] Cleaning previous build artifacts..."
sudo rm -f strace-go bpf/capture_manifest_generated.h cmd/strace-go/bpf_capture_manifest_generated.go cmd/strace-go/bpf_bpfeb.go cmd/strace-go/bpf_bpfeb.o cmd/strace-go/bpf_bpfel.go cmd/strace-go/bpf_bpfel.o cmd/strace-go/bpfhandlers_bpf*.go cmd/strace-go/bpfhandlers_bpf*.o cmd/strace-go/bpfenter_bpf*.go cmd/strace-go/bpfenter_bpf*.o cmd/strace-go/bpfenter_generic_bpf*.go cmd/strace-go/bpfenter_generic_bpf*.o cmd/strace-go/bpfenter_payload_bpf*.go cmd/strace-go/bpfenter_payload_bpf*.o cmd/strace-go/bpfenter_path_bpf*.go cmd/strace-go/bpfenter_path_bpf*.o cmd/strace-go/bpfenter_memory_bpf*.go cmd/strace-go/bpfenter_memory_bpf*.o cmd/strace-go/bpfenter_control_bpf*.go cmd/strace-go/bpfenter_control_bpf*.o cmd/strace-go/bpfenter_structured_bpf*.go cmd/strace-go/bpfenter_structured_bpf*.o cmd/strace-go/bpfexit_bpf*.go cmd/strace-go/bpfexit_bpf*.o cmd/strace-go/bpfrecvmsg_bpf*.go cmd/strace-go/bpfrecvmsg_bpf*.o pkg/meta/syscall_table.go pkg/meta/xlat_auto.go

echo "==> [2/3] Generating Syscall Table and eBPF bytecode..."
echo "    (sudo is required to read /sys/kernel/tracing and parse events)"
cd cmd/strace-go
sudo go generate ./...
cd ../..

echo "==> [3/3] Building strace-go binary..."
go build -o strace-go ./cmd/strace-go

echo "==> Build complete! Successfully created 'strace-go' executable."
echo "    Run it with: sudo ./strace-go <command>"
