package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFEnterCapabilityTranslationUnitsOwnDispatchHeaders(t *testing.T) {
	root := repoRootForTest(t)
	want := map[string][]string{
		"handlers_enter_generic.c":    {"#define STRACE_GO_ENTER_GENERIC 1", `#include "enter_dispatch.h"`},
		"handlers_enter_payload.c":    {"#define STRACE_GO_ENTER_PAYLOAD 1", `#include "enter_dispatch.h"`},
		"handlers_enter_path.c":       {"#define STRACE_GO_ENTER_PATH 1", `#include "enter_dispatch.h"`, `#include "mount_path_dispatch.h"`},
		"handlers_enter_memory.c":     {"#define STRACE_GO_ENTER_MEMORY 1", `#include "enter_dispatch.h"`, `#include "enter_fragment_dispatch.h"`, `#include "mmsg_enter_dispatch.h"`},
		"handlers_enter_control.c":    {"#define STRACE_GO_ENTER_CONTROL 1", `#include "enter_dispatch.h"`, `#include "nested_fd_path_dispatch.h"`},
		"handlers_enter_structured.c": {"#define STRACE_GO_ENTER_STRUCTURED 1", `#include "enter_dispatch.h"`, `#include "quota_dispatch.h"`},
	}
	for name, snippets := range want {
		source := readTextFile(t, filepath.Join(root, "bpf", name))
		if !strings.Contains(source, `#include "handler_common.h"`) {
			t.Fatalf("%s does not include common runtime", name)
		}
		for _, snippet := range snippets {
			if !strings.Contains(source, snippet) {
				t.Fatalf("%s is missing %q", name, snippet)
			}
		}
	}
}

func TestBPFEnterCapabilitySourcesDoNotIncludeForeignDispatchHeaders(t *testing.T) {
	root := repoRootForTest(t)
	foreign := map[string][]string{
		"handlers_enter_generic.c":    {`#include "enter_fragment_dispatch.h"`, `#include "nested_fd_path_dispatch.h"`, `#include "mmsg_enter_dispatch.h"`, `#include "mount_path_dispatch.h"`, `#include "quota_dispatch.h"`},
		"handlers_enter_payload.c":    {`#include "enter_fragment_dispatch.h"`, `#include "nested_fd_path_dispatch.h"`, `#include "mmsg_enter_dispatch.h"`, `#include "mount_path_dispatch.h"`, `#include "quota_dispatch.h"`},
		"handlers_enter_path.c":       {`#include "enter_fragment_dispatch.h"`, `#include "nested_fd_path_dispatch.h"`, `#include "mmsg_enter_dispatch.h"`, `#include "quota_dispatch.h"`},
		"handlers_enter_memory.c":     {`#include "nested_fd_path_dispatch.h"`, `#include "mount_path_dispatch.h"`, `#include "quota_dispatch.h"`},
		"handlers_enter_control.c":    {`#include "enter_fragment_dispatch.h"`, `#include "mmsg_enter_dispatch.h"`, `#include "mount_path_dispatch.h"`, `#include "quota_dispatch.h"`},
		"handlers_enter_structured.c": {`#include "enter_fragment_dispatch.h"`, `#include "nested_fd_path_dispatch.h"`, `#include "mmsg_enter_dispatch.h"`, `#include "mount_path_dispatch.h"`},
	}
	for name, snippets := range foreign {
		source := readTextFile(t, filepath.Join(root, "bpf", name))
		for _, snippet := range snippets {
			if strings.Contains(source, snippet) {
				t.Fatalf("%s includes foreign dispatch header %q", name, snippet)
			}
		}
	}
}

func equalHandlerFamilies(got, want []bpfHandlerFamily) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
