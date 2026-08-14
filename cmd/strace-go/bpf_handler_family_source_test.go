package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBPFHandlerFamilyTranslationUnitsKeepOwnership(t *testing.T) {
	root := repoRootForTest(t)
	sources := map[string]string{
		"exit":    readTextFile(t, filepath.Join(root, "bpf/handlers_exit.c")),
		"recvmsg": readTextFile(t, filepath.Join(root, "bpf/handlers_recvmsg.c")),
	}
	required := map[string][]string{
		"exit": {
			"#define STRACE_GO_HANDLER_EXIT 1",
			`#include "exit_dispatch.h"`,
			`#include "exit_direct_dispatch.h"`,
			`#include "quota_dispatch.h"`,
			`#include "mount_query_dispatch.h"`,
		},
		"recvmsg": {
			"#define STRACE_GO_HANDLER_RECVMSG 1",
			`#include "recvmsg_kretprobe_dispatch.h"`,
		},
	}
	for family, source := range sources {
		if !strings.Contains(source, `#include "handler_common.h"`) {
			t.Fatalf("%s handler does not include common runtime ownership", family)
		}
		for _, snippet := range required[family] {
			if !strings.Contains(source, snippet) {
				t.Fatalf("%s handler source is missing %q", family, snippet)
			}
		}
	}
	if strings.Contains(sources["exit"], `#include "enter_dispatch.h"`) ||
		strings.Contains(sources["recvmsg"], `#include "enter_dispatch.h"`) {
		t.Fatal("handler family translation units include a foreign dispatch family")
	}

	quota := readTextFile(t, filepath.Join(root, "bpf/quota_dispatch.h"))
	for _, snippet := range []string{
		"#if !defined(STRACE_GO_HANDLER_FAMILY) || defined(STRACE_GO_HANDLER_ENTER)",
		"#if !defined(STRACE_GO_HANDLER_FAMILY) || defined(STRACE_GO_HANDLER_EXIT)",
	} {
		if !strings.Contains(quota, snippet) {
			t.Fatalf("quota dispatch ownership guard missing %q", snippet)
		}
	}
}
