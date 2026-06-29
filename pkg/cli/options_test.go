package cli

import "testing"

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
