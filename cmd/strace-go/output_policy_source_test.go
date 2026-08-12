package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestOutputComponentsUsePolicyPorts(t *testing.T) {
	root := filepath.Join(repoRootForTest(t), "cmd/strace-go")
	policySource := readTextFile(t, filepath.Join(root, "output_policy.go"))
	for _, name := range []string{
		"traceFormatPolicy",
		"traceEventOutputPolicy",
		"traceSummaryPolicy",
		"traceExitPolicy",
	} {
		if !strings.Contains(policySource, "type "+name+" interface") {
			t.Fatalf("output policy must define %s", name)
		}
	}

	concreteOptions := regexp.MustCompile(`\*cli\.Options`)
	for _, name := range []string{
		"syscall_text_output.go",
		"syscall_json_output.go",
		"syscall_exit_pipeline.go",
		"exit_syscall_output.go",
		"run_finalizer.go",
		"command_exit_handler.go",
	} {
		source := readTextFile(t, filepath.Join(root, name))
		if concreteOptions.MatchString(source) {
			t.Fatalf("%s still exposes concrete CLI options", name)
		}
	}
}
