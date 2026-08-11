package main

import (
	"strings"
	"testing"
)

func TestBPFOpenCreatPayloadUsesDirectTLV(t *testing.T) {
	straceSource := readCombinedBPFSources(t)
	legacyCaptureArtifacts := legacyCaptureArtifactsForTest(t)
	directHeader := loadBPFSources(t).directHeader

	for _, snippet := range []string{
		"#define SYS_OPEN 2",
		"#define SYS_CREAT 85",
		"is_open_creat_path_direct_syscall(sys_id)",
		"sys_id == SYS_OPEN || sys_id == SYS_CREAT || sys_id == SYS_OPENAT",
		"capture_openat_path_tlv_direct(ptr, payload_offset, 0, args[0])",
		"capture_openat_path_tlv_direct(ptr, payload_offset, 1, args[1])",
	} {
		if !strings.Contains(straceSource, snippet) && !strings.Contains(directHeader, snippet) {
			t.Fatalf("BPF source missing open/creat direct snippet %q", snippet)
		}
	}

	for _, legacyRule := range []string{
		"syscalls: [open, creat",
		"case 2: /* open */",
		"case 85: /* creat */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("open/creat still uses old fixed-window rule %q", legacyRule)
		}
	}
}
