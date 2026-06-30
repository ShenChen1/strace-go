package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseCombinedVerboseTraceFlag(t *testing.T) {
	opts := ParseArgs([]string{"-veexecve", "/bin/true"})

	if !opts.Verbose {
		t.Fatal("combined -ve flag did not enable verbose output")
	}
	if !opts.TraceSyscalls["execve"] {
		t.Fatal("combined -ve flag did not configure execve tracing")
	}
	if len(opts.CmdArgs) != 1 || opts.CmdArgs[0] != "/bin/true" {
		t.Fatalf("CmdArgs = %#v", opts.CmdArgs)
	}
}

func TestParseTraceFDsLongFlag(t *testing.T) {
	opts := ParseArgs([]string{"--trace-fds=0,9", "--trace=dup", "/bin/true"})

	if opts.TraceFDsNegated {
		t.Fatal("TraceFDsNegated = true, want false")
	}
	if !opts.TraceFDs[0] || !opts.TraceFDs[9] || len(opts.TraceFDs) != 2 {
		t.Fatalf("TraceFDs = %#v, want {0, 9}", opts.TraceFDs)
	}
	if !opts.TraceSyscalls["dup"] {
		t.Fatal("trace syscall was not parsed after --trace-fds")
	}
}

func TestParseTraceFDNegationFromEFlag(t *testing.T) {
	opts := ParseArgs([]string{"-e", "trace-fd=!9", "/bin/true"})

	if !opts.TraceFDsNegated {
		t.Fatal("TraceFDsNegated = false, want true")
	}
	if !opts.TraceFDs[9] || len(opts.TraceFDs) != 1 {
		t.Fatalf("TraceFDs = %#v, want {9}", opts.TraceFDs)
	}
}

func TestParseFDSetsFromEFlagAlias(t *testing.T) {
	opts := ParseArgs([]string{"--trace=dup2", "-e", "fd=0,9", "/bin/true"})

	if opts.TraceFDsNegated {
		t.Fatal("TraceFDsNegated = true, want false")
	}
	if !opts.TraceFDs[0] || !opts.TraceFDs[9] || len(opts.TraceFDs) != 2 {
		t.Fatalf("TraceFDs = %#v, want {0, 9}", opts.TraceFDs)
	}
	if !opts.TraceSyscalls["dup2"] {
		t.Fatal("trace syscall was not preserved after -e fd")
	}
}

func TestParseVerboseDisabledFromEFlag(t *testing.T) {
	opts := ParseArgs([]string{"-e", "trace=capget,capset", "-e", "verbose=!capget,capset", "/bin/true"})

	if !opts.TraceSyscalls["capget"] || !opts.TraceSyscalls["capset"] {
		t.Fatalf("TraceSyscalls = %#v, want capget and capset", opts.TraceSyscalls)
	}
	if !opts.VerboseDisabled["capget"] || !opts.VerboseDisabled["capset"] {
		t.Fatalf("VerboseDisabled = %#v, want capget and capset disabled", opts.VerboseDisabled)
	}
	if opts.TraceSyscalls["verbose=!capget"] {
		t.Fatal("verbose qualifier was parsed as a syscall")
	}
}

func TestParseEventFormat(t *testing.T) {
	opts := ParseArgs([]string{"--event-format=json", "/bin/true"})

	if opts.EventFormat != EventFormatJSON {
		t.Fatalf("EventFormat = %q, want %q", opts.EventFormat, EventFormatJSON)
	}
	if opts.DebugEvents {
		t.Fatal("DebugEvents = true, want false")
	}
}

func TestParseDefaultsToTextEventFormat(t *testing.T) {
	opts := ParseArgs([]string{"/bin/true"})

	if opts.EventFormat != EventFormatText {
		t.Fatalf("EventFormat = %q, want %q", opts.EventFormat, EventFormatText)
	}
}

func TestParseDebugEventsAlias(t *testing.T) {
	opts := ParseArgs([]string{"--debug-events", "/bin/true"})

	if opts.EventFormat != EventFormatJSON {
		t.Fatalf("EventFormat = %q, want %q", opts.EventFormat, EventFormatJSON)
	}
	if !opts.DebugEvents {
		t.Fatal("DebugEvents = false, want true")
	}
}

func TestParseModeFlagRejected(t *testing.T) {
	if os.Getenv("STRACE_GO_PARSE_MODE_EXIT") == "1" {
		ParseArgs([]string{"--mode=compat", "/bin/true"})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestParseModeFlagRejected")
	cmd.Env = append(os.Environ(), "STRACE_GO_PARSE_MODE_EXIT=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("ParseArgs(--mode=compat) exit = %v, want status 1; stderr=%q", err, stderr.String())
	}
	msg := stderr.String()
	if !strings.Contains(msg, "--mode has been removed") || !strings.Contains(msg, "pure eBPF") {
		t.Fatalf("stderr = %q, want removed-mode pure-eBPF message", msg)
	}
}
