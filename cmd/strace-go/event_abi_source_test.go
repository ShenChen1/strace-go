package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestEventABIConstantsHaveOneGeneratedSource(t *testing.T) {
	root := repoRootForTest(t)
	generatedHeader := readTextFile(t, filepath.Join(root, "bpf/event_abi_generated.h"))
	generatedGo := readTextFile(t, filepath.Join(root, "cmd/strace-go/event_abi_generated.go"))
	normalizedGeneratedGo := strings.Join(strings.Fields(generatedGo), " ")
	for _, required := range []string{
		"#define EVENT_VERSION 2",
		"#define EVENT_V2_HEADER_LEN 56",
		"#define EVENT_V2_HEADER_COMM_OFFSET 40",
		"#define EVENT_V2_COMM_SIZE 16",
		"#define EVENT_V2_HEADER_VERSION_OFFSET 0",
		"#define EVENT_V2_EXIT_STACK_ID_OFFSET 72",
		"#define EVENT_V2_ARGS_SIZE 48",
		"#define PAYLOAD_TLV_KIND_FD_PATH 9",
		"#define EVENT_FLAG_ENTER_FRAGMENT 32",
		"#define EVENT_FLAG_KVM_EXIT 64",
		"#define CONFIG_KVM_EXIT 2048",
		"#define CONFIG_SYSCALL_FILTER_STRICT_UNKNOWN 4096",
	} {
		if !strings.Contains(generatedHeader, required) {
			t.Fatalf("generated event ABI header missing %q", required)
		}
	}
	for _, required := range []string{
		"traceEventV2Version = 2",
		"traceEventV2HeaderVersionOffset = 0",
		"traceEventV2ExitStackIDOffset = 72",
		"traceEventV2ArgsSize = 48",
		"bpfEventFlagPayloadTLV uint32 = 2",
		"bpfEventFlagEnterFragment uint32 = 32",
		"bpfEventFlagKVMExit uint32 = 64",
		"bpfConfigEmitLifecycle = 32",
		"bpfConfigDecodePIDComm = 512",
		"bpfConfigKVMExit = 2048",
		"bpfConfigSyscallFilterStrictUnknown = 4096",
		"traceEventV2HeaderCommOffset = 40",
		"traceEventV2CommSize = 16",
	} {
		if !strings.Contains(normalizedGeneratedGo, required) {
			t.Fatalf("generated event ABI Go missing %q", required)
		}
	}

	for _, file := range []string{
		"bpf/runtime_abi.h",
		"bpf/payload_tlv.h",
		"cmd/strace-go/main.go",
		"cmd/strace-go/event_json.go",
		"cmd/strace-go/event_payload_tlv.go",
		"cmd/strace-go/trace_event_v2_decoder.go",
		"cmd/strace-go/bpf_map_catalog.go",
	} {
		source := readTextFile(t, filepath.Join(root, file))
		for _, forbidden := range []string{
			"#define EVENT_VERSION 2",
			"#define EVENT_FLAG_PAYLOAD_TLV 2",
			"#define CONFIG_CAPTURE_STACK 1",
			"#define FILTER_TASK_TRACKED 1",
			"#define EVENT_V2_HEADER_LEN 56",
			"#define PAYLOAD_TLV_HEADER_SIZE 32",
			"bpfConfigCaptureStack         = 1 << 0",
			"bpfEventTypeEnter        uint16 = 1",
			"payloadTLVHeaderSize       = 32",
			"traceEventV2Version             = 2",
			"const bpfFilterTaskTracked uint32 = 1",
		} {
			if strings.Contains(source, forbidden) {
				t.Fatalf("%s still contains duplicated protocol constant %q", file, forbidden)
			}
		}
	}

	decoder := readTextFile(t, filepath.Join(root, "cmd/strace-go/trace_event_v2_decoder.go"))
	for _, forbidden := range []string{
		"rawSample[0:2]",
		"body[64:68]",
		"body[72:76]",
		"i*8 : i*8+8",
	} {
		if strings.Contains(decoder, forbidden) {
			t.Fatalf("decoder still contains literal event v2 offset %q", forbidden)
		}
	}
	runtimeABI := readTextFile(t, filepath.Join(root, "bpf/runtime_abi.h"))
	for _, required := range []string{
		"_Static_assert(sizeof(struct event_v2_header)",
		"__builtin_offsetof(struct syscall_enter_event_v2, capture_flags)",
		"__builtin_offsetof(struct syscall_compact_enter_event_v2, args)",
		"__builtin_offsetof(struct syscall_exit_event_v2, capture_flags)",
		"__builtin_offsetof(struct syscall_exit_event_v2, reserved)",
	} {
		if !strings.Contains(runtimeABI, required) {
			t.Fatalf("runtime ABI is missing event v2 layout assertion %q", required)
		}
	}
}
