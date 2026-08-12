package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestTextRenderingComponentsUseRenderPolicyPorts(t *testing.T) {
	root := filepath.Join(repoRootForTest(t), "cmd/strace-go")
	policySource := readTextFile(t, filepath.Join(root, "output_policy.go"))
	for _, name := range []string{"traceRenderPolicy", "traceFollowForkPolicy"} {
		if !strings.Contains(policySource, "type "+name+" interface") {
			t.Fatalf("render policy must define %s", name)
		}
	}

	concreteOptions := regexp.MustCompile(`\*cli\.Options`)
	for _, name := range []string{
		"text_renderer.go",
		"time_formatter.go",
		"exec_syscall_output.go",
	} {
		source := readTextFile(t, filepath.Join(root, name))
		if concreteOptions.MatchString(source) {
			t.Fatalf("%s still exposes concrete CLI options", name)
		}
	}
}
