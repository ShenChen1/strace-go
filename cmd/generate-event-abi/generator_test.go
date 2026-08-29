package main

import (
	"bytes"
	"go/format"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProtocolConstantsHaveUniqueNames(t *testing.T) {
	if err := validateProtocolConstants(protocolConstants); err != nil {
		t.Fatalf("validateProtocolConstants() error = %v", err)
	}
}

func TestWriteProtocolHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "event_abi_generated.h")
	if err := writeProtocolHeader(path); err != nil {
		t.Fatalf("writeProtocolHeader() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated header: %v", err)
	}
	got := string(data)
	for _, want := range []string{
		"#define EVENT_VERSION 2",
		"#define EVENT_FLAG_COMPACT_ENTER 16",
		"#define CONFIG_ELIDE_PLAIN_ENTER 128",
		"#define CONFIG_EMIT_SIGNAL 256",
		"#define CONFIG_DECODE_PID_COMM 512",
		"#define EVENT_V2_HEADER_TS_NS_OFFSET 32",
		"#define EVENT_V2_HEADER_COMM_OFFSET 40",
		"#define EVENT_V2_COMM_SIZE 16",
		"#define EVENT_V2_EXIT_STACK_ID_OFFSET 72",
		"#define EVENT_TYPE_SIGNAL 4",
		"#define EVENT_V2_SIGNAL_SENDER_UID_OFFSET 16",
		"#define PAYLOAD_TLV_KIND_FD_PATH 9",
		"#define PAYLOAD_TLV_FD_PATH_NESTED_ARG_INDEX 0xfffd",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("generated header missing %q:\n%s", want, got)
		}
	}
}

func TestWriteProtocolGo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "event_abi_generated.go")
	if err := writeProtocolGo(path); err != nil {
		t.Fatalf("writeProtocolGo() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read generated Go: %v", err)
	}
	formatted, err := format.Source(data)
	if err != nil {
		t.Fatalf("format generated Go: %v", err)
	}
	if !bytes.Equal(data, formatted) {
		t.Fatal("generated Go is not gofmt-formatted")
	}
	got := strings.Join(strings.Fields(string(data)), " ")
	for _, want := range []string{
		"traceEventV2Version = 2",
		"bpfEventFlagCompactEnter uint32 = 16",
		"bpfConfigElidePlainEnter = 128",
		"bpfConfigEmitSignal = 256",
		"bpfConfigDecodePIDComm = 512",
		"traceEventV2HeaderTSNSOffset = 32",
		"traceEventV2HeaderCommOffset = 40",
		"traceEventV2CommSize = 16",
		"traceEventV2ExitStackIDOffset = 72",
		"bpfEventTypeSignal uint16 = 4",
		"traceEventV2SignalSenderUIDOffset = 16",
		"payloadTLVKindFDPath = 9",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("generated Go missing %q:\n%s", want, got)
		}
	}
}

func TestProtocolWritersReportWriteError(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skipf("/dev/full unavailable: %v", err)
	}
	if err := writeProtocolHeader("/dev/full"); err == nil {
		t.Fatal("writeProtocolHeader(/dev/full) error = nil")
	}
	if err := writeProtocolGo("/dev/full"); err == nil {
		t.Fatal("writeProtocolGo(/dev/full) error = nil")
	}
}
