package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseTipsDefaultsAndSelectors(t *testing.T) {
	defaults := ParseArgs([]string{"--tips", "/bin/true"})
	if defaults.TipsMode != TipsModeCompact || defaults.TipsID != TipsIDRandom {
		t.Fatalf("default tips = mode:%q id:%d", defaults.TipsMode, defaults.TipsID)
	}

	selected := ParseArgs([]string{"--tips=FORMAT:FULL,id:7", "/bin/true"})
	if selected.TipsMode != TipsModeFull || selected.TipsID != 7 {
		t.Fatalf("selected tips = mode:%q id:%d", selected.TipsMode, selected.TipsID)
	}
}

func TestParseRepeatedTipsOptionsPreservesUnchangedSelector(t *testing.T) {
	opts := ParseArgs([]string{"--tips=id:3", "--tips=format:none", "/bin/true"})
	if opts.TipsMode != TipsModeNone || opts.TipsID != 3 {
		t.Fatalf("repeated tips = mode:%q id:%d", opts.TipsMode, opts.TipsID)
	}
}

func TestParseInvalidTipsSelectorRejected(t *testing.T) {
	if os.Getenv("STRACE_GO_PARSE_INVALID_TIPS") == "1" {
		ParseArgs([]string{"--tips=id:-1", "/bin/true"})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestParseInvalidTipsSelectorRejected")
	cmd.Env = append(os.Environ(), "STRACE_GO_PARSE_INVALID_TIPS=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("invalid tips exit = %v, want status 1", err)
	}
	if !strings.Contains(stderr.String(), "invalid --tips argument: 'id:-1'") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
