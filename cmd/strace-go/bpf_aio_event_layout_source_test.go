package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFAioDirectModulesOwnResponsibilities(t *testing.T) {
	root := repoRootForTest(t)
	read := func(name string) string {
		return readTextFile(t, filepath.Join(root, "bpf", name))
	}
	strace := readTextFile(t, filepath.Join(root, "bpf", "strace.c"))

	facade := read("syscall_aio_direct_event_v2.h")
	core := read("syscall_aio_core_direct_event_v2.h")
	capture := read("syscall_aio_capture_direct_event_v2.h")
	cancelCapture := read("syscall_aio_cancel_capture_direct_event_v2.h")
	emit := read("syscall_aio_emit_direct_event_v2.h")
	geteventsFacade := read("syscall_aio_getevents_direct_event_v2.h")
	geteventsCapture := read("syscall_aio_getevents_capture_direct_event_v2.h")
	geteventsEmit := read("syscall_aio_getevents_emit_direct_event_v2.h")

	for name, source := range map[string]string{
		"syscall_aio_direct_event_v2.h":                   facade,
		"syscall_aio_core_direct_event_v2.h":              core,
		"syscall_aio_capture_direct_event_v2.h":           capture,
		"syscall_aio_cancel_capture_direct_event_v2.h":    cancelCapture,
		"syscall_aio_emit_direct_event_v2.h":              emit,
		"syscall_aio_getevents_direct_event_v2.h":         geteventsFacade,
		"syscall_aio_getevents_capture_direct_event_v2.h": geteventsCapture,
		"syscall_aio_getevents_emit_direct_event_v2.h":    geteventsEmit,
	} {
		if !strings.Contains(source, "#ifndef STRACE_GO_") || !strings.Contains(source, "#endif") {
			t.Fatalf("%s must have an include guard", name)
		}
	}

	for _, include := range []string{
		`#include "syscall_aio_core_direct_event_v2.h"`,
		`#include "syscall_aio_capture_direct_event_v2.h"`,
		`#include "syscall_aio_cancel_capture_direct_event_v2.h"`,
		`#include "syscall_aio_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(facade, include) {
			t.Fatalf("AIO facade missing %q", include)
		}
	}
	for _, include := range []string{
		`#include "syscall_aio_getevents_capture_direct_event_v2.h"`,
		`#include "syscall_aio_getevents_emit_direct_event_v2.h"`,
	} {
		if !strings.Contains(geteventsFacade, include) {
			t.Fatalf("AIO getevents facade missing %q", include)
		}
	}
	geteventsInclude := strings.Index(strace, `#include "syscall_aio_getevents_direct_event_v2.h"`)
	aioInclude := strings.Index(strace, `#include "syscall_aio_direct_event_v2.h"`)
	if geteventsInclude < 0 || aioInclude < 0 || geteventsInclude >= aioInclude {
		t.Fatal("strace.c must include AIO getevents helpers before the AIO facade")
	}
	for _, snippet := range []string{
		"is_aio_setup_direct_syscall(",
		"is_aio_submit_direct_syscall(",
		"is_aio_cancel_direct_syscall(",
		"is_aio_direct_syscall(",
	} {
		if !strings.Contains(core, snippet) {
			t.Fatalf("AIO core module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"capture_aio_setup_ctx_tlv_direct(",
		"capture_aio_submit_pointers_tlv_direct(",
		"capture_aio_submit_iocb_iovec_tlv_direct(",
		"capture_aio_submit_iocb_buf_tlv_direct(",
	} {
		if !strings.Contains(capture, snippet) {
			t.Fatalf("AIO capture module missing %q", snippet)
		}
	}
	if !strings.Contains(cancelCapture, "capture_aio_cancel_iocb_tlv_direct(") {
		t.Fatal("AIO cancel capture module missing cancel iocb helper")
	}
	for _, snippet := range []string{
		"capture_aio_getevents_timeout_tlv_direct(",
		"capture_aio_getevents_events_tlv_direct(",
		"capture_aio_pgetevents_sigset_tlv_direct(",
		"capture_aio_pgetevents_sigmask_tlv_direct(",
	} {
		if !strings.Contains(geteventsCapture, snippet) {
			t.Fatalf("AIO getevents capture module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_aio_submit_iovec_enter_event_v2_direct(",
		"emit_aio_cancel_enter_event_v2_direct(",
		"emit_aio_enter_event_v2_direct(",
		"emit_aio_setup_exit_event_v2_direct(",
	} {
		if !strings.Contains(emit, snippet) {
			t.Fatalf("AIO emit module missing %q", snippet)
		}
	}
	for _, snippet := range []string{
		"emit_aio_getevents_enter_event_v2_direct(",
		"emit_aio_pgetevents_enter_event_v2_direct(",
		"emit_aio_getevents_exit_event_v2_direct(",
	} {
		if !strings.Contains(geteventsEmit, snippet) {
			t.Fatalf("AIO getevents emit module missing %q", snippet)
		}
	}
	for _, forbidden := range []string{
		"static __always_inline int is_aio_direct_syscall(",
		"static __always_inline u32 capture_aio_setup_ctx_tlv_direct(",
		"static __always_inline void emit_aio_enter_event_v2_direct(",
		"static __always_inline u32 capture_aio_cancel_iocb_tlv_direct(",
		"static __always_inline u32 capture_aio_getevents_timeout_tlv_direct(",
		"static __always_inline void emit_aio_getevents_enter_event_v2_direct(",
	} {
		if strings.Contains(facade, forbidden) {
			t.Fatalf("AIO facade must not own implementation %q", forbidden)
		}
	}
}

func TestBPFAioDirectModulesStayWithinFileLimit(t *testing.T) {
	root := repoRootForTest(t)
	for _, name := range []string{
		"syscall_aio_direct_event_v2.h",
		"syscall_aio_core_direct_event_v2.h",
		"syscall_aio_capture_direct_event_v2.h",
		"syscall_aio_cancel_capture_direct_event_v2.h",
		"syscall_aio_emit_direct_event_v2.h",
		"syscall_aio_getevents_direct_event_v2.h",
		"syscall_aio_getevents_capture_direct_event_v2.h",
		"syscall_aio_getevents_emit_direct_event_v2.h",
	} {
		source := readTextFile(t, filepath.Join(root, "bpf", name))
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("bpf/%s lines = %d, want <= 500", name, lines)
		}
	}
}
