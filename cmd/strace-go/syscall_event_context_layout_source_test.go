package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSyscallEventContextResponsibilitiesStaySplit(t *testing.T) {
	root := filepath.Join(repoRootForTest(t), "cmd/strace-go")
	sources := map[string]string{}
	for _, name := range []string{
		"syscall_event_context.go",
		"syscall_event_context_handler.go",
		"syscall_event_context_effects.go",
		"syscall_event_context_policy.go",
	} {
		source := readTextFile(t, filepath.Join(root, name))
		sources[name] = source
		if lines := strings.Count(source, "\n") + 1; lines > 500 {
			t.Fatalf("%s lines = %d, want <= 500", name, lines)
		}
	}

	for name, snippet := range map[string]string{
		"syscall_event_context.go":         "func newSyscallEventContextFromViewWithDeps(",
		"syscall_event_context_handler.go": "func (ev syscallEventContext) newHandlerContext(",
		"syscall_event_context_effects.go": "func (ev syscallEventContext) updateFDState(",
		"syscall_event_context_policy.go":  "func (ev syscallEventContext) shouldEmitStatus(",
	} {
		if !strings.Contains(sources[name], snippet) {
			t.Fatalf("%s missing responsibility owner %q", name, snippet)
		}
	}

	for _, snippet := range []string{
		"func (ev syscallEventContext) newHandlerContext(",
		"func (ev syscallEventContext) updateFDState(",
		"func (ev syscallEventContext) shouldEmitStatus(",
	} {
		if strings.Contains(sources["syscall_event_context.go"], snippet) {
			t.Fatalf("core context file regained responsibility %q", snippet)
		}
	}
}
