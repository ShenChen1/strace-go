package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandBootstrapDoesNotDependOnCLIOptions(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/session.go"))
	if strings.Contains(source, "strace-go/pkg/cli") || strings.Contains(source, "*cli.Options") {
		t.Fatal("command bootstrap in session.go must not depend on cli.Options")
	}
	if strings.Contains(source, "func newTraceCommand(opts") || strings.Contains(source, "func startTraceCmd(opts") {
		t.Fatal("command bootstrap must consume traceCommandSpec instead of cli.Options")
	}
}
