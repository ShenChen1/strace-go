package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestEventFilteringUsesTraceFilterPort(t *testing.T) {
	root := filepath.Join(repoRootForTest(t), "cmd/strace-go")
	filterSource := readTextFile(t, filepath.Join(root, "trace_filter.go"))
	if !strings.Contains(filterSource, "type traceFilterOptions interface") {
		t.Fatal("event filtering must define a narrow trace filter port")
	}

	concreteOptions := regexp.MustCompile(`\bopts\s+\*cli\.Options`)
	for _, name := range []string{"event_utils.go", "syscall_event_context.go"} {
		source := readTextFile(t, filepath.Join(root, name))
		if concreteOptions.MatchString(source) {
			t.Fatalf("%s still exposes concrete CLI options in event filtering", name)
		}
		if !strings.Contains(source, "filter traceFilterOptions") {
			t.Fatalf("%s must consume traceFilterOptions", name)
		}
	}
}
