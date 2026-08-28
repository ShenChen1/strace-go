package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseSignalSelectorAliases(t *testing.T) {
	for _, args := range [][]string{
		{"--signal=!SIGCHLD,SIGCONT", "/bin/true"},
		{"-e", "signal=!chld,cont", "/bin/true"},
	} {
		opts := ParseArgs(args)
		if !opts.SignalConfigured || !opts.SignalSetIsNegated || opts.SignalMatchesAll {
			t.Fatalf("signal selector state = configured:%v negated:%v all:%v", opts.SignalConfigured, opts.SignalSetIsNegated, opts.SignalMatchesAll)
		}
		if !opts.TraceSignals[17] || !opts.TraceSignals[18] || len(opts.TraceSignals) != 2 {
			t.Fatalf("signal selector = %#v, want SIGCHLD and SIGCONT", opts.TraceSignals)
		}
	}
}

func TestParseSignalSelectorAllAndNone(t *testing.T) {
	all := ParseArgs([]string{"--signal=!none", "/bin/true"})
	if !all.SignalConfigured || !all.SignalMatchesAll || all.SignalSetIsNegated {
		t.Fatalf("signal !none = configured:%v all:%v negated:%v", all.SignalConfigured, all.SignalMatchesAll, all.SignalSetIsNegated)
	}

	none := ParseArgs([]string{"--signal=", "/bin/true"})
	if !none.SignalConfigured || none.SignalMatchesAll || none.SignalSetIsNegated || len(none.TraceSignals) != 0 {
		t.Fatalf("empty signal set = configured:%v all:%v negated:%v values:%v", none.SignalConfigured, none.SignalMatchesAll, none.SignalSetIsNegated, none.TraceSignals)
	}
}

func TestParseInvalidSignalRejected(t *testing.T) {
	invalid := os.Getenv("STRACE_GO_INVALID_SIGNAL")
	if invalid != "" {
		ParseArgs([]string{"--signal=" + invalid, "/bin/true"})
		return
	}

	for _, value := range []string{"invalid_signal_name", "-1", "256", "9,chdir"} {
		t.Run(value, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestParseInvalidSignalRejected")
			cmd.Env = append(os.Environ(), "STRACE_GO_INVALID_SIGNAL="+value)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("ParseArgs(%q) exit = %v, want status 1; stderr=%q", value, err, stderr.String())
			}
			if !strings.Contains(stderr.String(), "invalid signal") {
				t.Fatalf("stderr = %q, want invalid signal diagnostic", stderr.String())
			}
		})
	}
}
