package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFKeyctlUsesOperationSpecificDirectPayload(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}
	facade := read("syscall_key_direct_event_v2.h")
	capture := read("syscall_key_capture_direct_event_v2.h")
	emit := read("syscall_key_emit_direct_event_v2.h")
	numbers := read("syscall_numbers_generated.h")
	routes := readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_routes.go"))
	routes += "\n" + readTextFile(t, filepath.Join(root, "cmd/strace-go/bpf_capture_manifest_generated.go"))
	routes = strings.Join(strings.Fields(routes), " ")
	for _, snippet := range []string{
		"#define SYS_KEYCTL 250",
		"KEYCTL_JOIN_SESSION_KEYRING",
		"KEYCTL_UPDATE",
		"KEYCTL_SEARCH",
		"KEYCTL_DESCRIBE",
		"KEYCTL_READ",
		"KEYCTL_CAPABILITIES",
		"keyctl_output_arg_index(",
		"keyctl_output_user_ptr(",
		"keyctl_output_user_len(",
		"p->args[2]",
		"p->args[3]",
		"is_keyctl_direct_syscall(",
		"capture_keyctl_payload_tlv_direct(",
		"capture_keyctl_output_tlv_direct(",
		"emit_keyctl_exit_event_v2_direct(",
		`"keyctl": {enterSlot: enterProgKey, exitSlot: exitProgIO, standaloneExitElision: false}`,
	} {
		if !strings.Contains(facade+capture+emit+numbers+routes, snippet) {
			t.Fatalf("keyctl direct source missing %q", snippet)
		}
	}
}
