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
