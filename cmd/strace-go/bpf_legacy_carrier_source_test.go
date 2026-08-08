package main

import (
	"strings"
	"testing"
)

func TestBPFDirectSyscallsHaveNoLegacyFixedWindowRules(t *testing.T) {
	legacyCaptureArtifacts := loadBPFSources(t).legacyCaptureArtifacts
	for _, legacyRule := range []string{
		"syscalls: [getcwd]",
		"syscalls: [clock_gettime, clock_getres]",
		"syscalls: [gettimeofday]",
		"syscalls: [getrlimit]",
		"syscalls: [stat, lstat]",
		"syscalls: [fstat]",
		"syscalls: [newfstatat]",
		"syscalls: [pipe, pipe2]",
		"syscalls: [prlimit64]",
		"syscalls: [readlink]",
		"syscalls: [readlinkat]",
		"syscalls: [setrlimit]",
		"syscalls: [socketpair]",
		"syscalls: [statfs]",
		"syscalls: [fstatfs]",
		"syscalls: [sysinfo]",
		"syscalls: [uname]",
		"syscalls: [read, pread64]",
		"syscalls: [write, pwrite64]",
		"syscalls: [waitid]",
		"syscalls: [rt_sigaction]",
		"syscalls: [rt_sigprocmask]",
		"syscalls: [rt_sigsuspend]",
		"syscalls: [chdir, execve]",
		"syscalls: [openat, execveat]",
		"case 0: /* read */",
		"case 1: /* write */",
		"case 4: /* stat */",
		"case 5: /* fstat */",
		"case 6: /* lstat */",
		"case 13: /* rt_sigaction */",
		"case 14: /* rt_sigprocmask */",
		"case 17: /* pread64 */",
		"case 18: /* pwrite64 */",
		"case 22: /* pipe */",
		"case 59: /* execve */",
		"case 53: /* socketpair */",
		"case 63: /* uname */",
		"case 79: /* getcwd */",
		"case 89: /* readlink */",
		"case 96: /* gettimeofday */",
		"case 97: /* getrlimit */",
		"case 99: /* sysinfo */",
		"case 130: /* rt_sigsuspend */",
		"case 137: /* statfs */",
		"case 138: /* fstatfs */",
		"case 160: /* setrlimit */",
		"case 228: /* clock_gettime */",
		"case 229: /* clock_getres */",
		"case 247: /* waitid */",
		"case 257: /* openat */",
		"case 262: /* newfstatat */",
		"case 267: /* readlinkat */",
		"case 293: /* pipe2 */",
		"case 302: /* prlimit64 */",
		"case 322: /* execveat */",
	} {
		if strings.Contains(legacyCaptureArtifacts, legacyRule) {
			t.Fatalf("direct path/exec syscall still uses old fixed-window rule %q", legacyRule)
		}
	}
}

func TestBPFDirectEventsPreserveFlagsAndDropLegacyCarrier(t *testing.T) {
	src := loadBPFSources(t)
	straceSource := src.straceSource
	directHeader := src.directHeader
	if !strings.Contains(directHeader, "flags |= EVENT_FLAG_PAYLOAD_TLV") ||
		!strings.Contains(directHeader, "u16 flags = EVENT_FLAG_GENERIC_ENTER") {
		t.Fatal("direct enter helpers should preserve generic enter and payload TLV flags")
	}
	if !strings.Contains(straceSource, "header->event_type = EVENT_TYPE_LIFECYCLE;") ||
		!strings.Contains(straceSource, "body->action = kind;") {
		t.Fatal("lifecycle events should build event v2 fields without the bpf_event carrier")
	}
	if strings.Contains(straceSource, "lifecycle_action") {
		t.Fatal("bpf_event carrier should not retain lifecycle_action")
	}
	if strings.Contains(straceSource, "e->ptr") {
		t.Fatal("bpf_event carrier should not retain raw pointer field")
	}
	for _, legacyCarrier := range []string{
		`#include "syscall_capture.h"`,
		"struct bpf_event",
		"} heap SEC(\".maps\")",
		"emit_syscall_event_v2(",
		"emit_event(",
		"CAPTURE_ARGS_ENTER(",
		"CAPTURE_ARGS_EXIT(",
	} {
		if strings.Contains(straceSource, legacyCarrier) {
			t.Fatalf("BPF runtime should not retain fixed-window carrier artifact %q", legacyCarrier)
		}
	}
}
