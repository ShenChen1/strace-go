package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseNamespaceNewOptions(t *testing.T) {
	for _, args := range [][]string{
		{"-e", "namespace=new", "/bin/true"},
		{"--namespace=new", "/bin/true"},
		{"--namespace", "new", "/bin/true"},
	} {
		opts := ParseArgs(args)
		if !opts.NamespaceNew {
			t.Fatalf("ParseArgs(%v) NamespaceNew = false", args)
		}
	}
}

func TestParseNamespaceRejectsUnsupportedValue(t *testing.T) {
	if os.Getenv("STRACE_GO_NAMESPACE_INVALID") != "" {
		ParseArgs([]string{"-e", "namespace=old", "/bin/true"})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestParseNamespaceRejectsUnsupportedValue")
	cmd.Env = append(os.Environ(), "STRACE_GO_NAMESPACE_INVALID=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("invalid namespace exit = %v, want status 1; stderr=%q", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid -e namespace= argument: 'old'") {
		t.Fatalf("stderr = %q, want upstream-compatible namespace error", stderr.String())
	}
}
