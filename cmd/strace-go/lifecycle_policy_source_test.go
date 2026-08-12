package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLifecycleComponentsUseSessionPolicyPorts(t *testing.T) {
	root := filepath.Join(repoRootForTest(t), "cmd/strace-go")
	policySource := readTextFile(t, filepath.Join(root, "output_policy.go"))
	for _, name := range []string{"traceLifecyclePolicy", "traceReadyPolicy"} {
		if !strings.Contains(policySource, "type "+name+" interface") {
			t.Fatalf("lifecycle policy must define %s", name)
		}
	}

	concreteOptions := regexp.MustCompile(`\*cli\.Options`)
	for _, name := range []string{
		"lifecycle_event_handler.go",
		"json_event_writer.go",
		"session_run.go",
	} {
		source := readTextFile(t, filepath.Join(root, name))
		if concreteOptions.MatchString(source) {
			t.Fatalf("%s still exposes concrete CLI options", name)
		}
	}
}
