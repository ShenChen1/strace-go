package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"strace-go/pkg/meta"
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

func TestParseCombinedShortFlags(t *testing.T) {
	opts := ParseArgs([]string{"-ct", "/bin/true"})

	if !opts.SummaryOnly || opts.PrintTimeMode != 1 {
		t.Fatalf("combined flags = summary:%v time:%d, want true/1", opts.SummaryOnly, opts.PrintTimeMode)
	}
}

func TestParseImplementedLongAliases(t *testing.T) {
	opts := ParseArgs([]string{
		"--follow-forks",
		"--successful-only",
		"--columns=48",
		"--output=trace.log",
		"--string-limit=64",
		"--const-print-style=raw",
		"--relative-timestamps",
		"--syscall-times",
		"--strings-in-hex=all",
		"--status=successful",
		"--read=0",
		"--write=1",
		"/bin/true",
	})

	if !opts.FollowForks || !opts.SuccessfulOnly {
		t.Fatalf("long boolean aliases = follow:%v successful:%v, want true/true", opts.FollowForks, opts.SuccessfulOnly)
	}
	if opts.AlignCol != 48 || opts.OutFile != "trace.log" || opts.StringLimit != 64 || opts.XlatFormat != "raw" {
		t.Fatalf("long value aliases = column:%d output:%q limit:%d xlat:%q", opts.AlignCol, opts.OutFile, opts.StringLimit, opts.XlatFormat)
	}
	if !opts.PrintRelativeTime || !opts.PrintSyscallTime || opts.HexEscapeMode != 2 {
		t.Fatalf("long render aliases = relative:%v duration:%v hex:%d", opts.PrintRelativeTime, opts.PrintSyscallTime, opts.HexEscapeMode)
	}
	if !opts.TraceStatus["successful"] || !opts.TraceReadFD(0) || !opts.TraceWriteFD(1) {
		t.Fatalf("long qualifier aliases = status:%v read:%v write:%v", opts.TraceStatus, opts.TraceReadFDs, opts.TraceWriteFDs)
	}
}

func TestParseLongSummaryAliases(t *testing.T) {
	if opts := ParseArgs([]string{"--summary-only", "/bin/true"}); !opts.SummaryOnly {
		t.Fatal("--summary-only did not enable summary-only mode")
	}
	if opts := ParseArgs([]string{"--summary", "/bin/true"}); !opts.SummaryAndPrint {
		t.Fatal("--summary did not enable summary-and-print mode")
	}
	if opts := ParseArgs([]string{"--failed-only", "/bin/true"}); !opts.FailedOnly {
		t.Fatal("--failed-only did not enable failed-only filtering")
	}
}

func TestParseOptionTerminator(t *testing.T) {
	opts := ParseArgs([]string{"-f", "--", "-command", "argument"})

	if !opts.FollowForks {
		t.Fatal("-f did not enable fork following")
	}
	if got := strings.Join(opts.CmdArgs, " "); got != "-command argument" {
		t.Fatalf("CmdArgs = %q, want option-terminated command", got)
	}
}

func TestParseArgv0(t *testing.T) {
	opts := ParseArgs([]string{"--argv0=sample", "/bin/true"})
	if !opts.Argv0Set || opts.Argv0 != "sample" {
		t.Fatalf("argv0 = set:%v value:%q, want true/sample", opts.Argv0Set, opts.Argv0)
	}

	empty := ParseArgs([]string{"--argv0=", "/bin/true"})
	if !empty.Argv0Set || empty.Argv0 != "" {
		t.Fatalf("empty argv0 = set:%v value:%q, want true/empty", empty.Argv0Set, empty.Argv0)
	}
}

func TestParseSyscallNumber(t *testing.T) {
	for _, flag := range []string{"-n", "--syscall-number"} {
		if opts := ParseArgs([]string{flag, "/bin/true"}); !opts.PrintSyscallNumber {
			t.Fatalf("%s did not enable syscall-number output", flag)
		}
	}
}

func TestParseArgumentNames(t *testing.T) {
	for _, flag := range []string{"-N", "--arg-names"} {
		if opts := ParseArgs([]string{flag, "/bin/true"}); !opts.PrintArgNames {
			t.Fatalf("%s did not enable argument-name output", flag)
		}
	}
}

func TestParseTraceClassAndAliases(t *testing.T) {
	opts := ParseArgs([]string{"-e", "trace=%process,rename", "/bin/true"})

	if !opts.TraceSyscalls["execve"] {
		t.Fatalf("process trace class did not include execve: %#v", opts.TraceSyscalls)
	}
	if !opts.TraceSyscalls["rename"] || !opts.TraceSyscalls["renameat"] || !opts.TraceSyscalls["renameat2"] {
		t.Fatalf("rename aliases missing from trace set: %#v", opts.TraceSyscalls)
	}
}

func TestParseTraceSetReplacesPreviousSelector(t *testing.T) {
	opts := ParseArgs([]string{"-e/", "-e42", "/bin/true"})
	want := meta.SyscallTable[42].Name

	if !opts.TraceConfigured || opts.TraceMatchesAll || opts.TraceSetIsNegated {
		t.Fatalf("trace selector state = configured:%v all:%v negated:%v", opts.TraceConfigured, opts.TraceMatchesAll, opts.TraceSetIsNegated)
	}
	if len(opts.TraceSyscallRegexps) != 0 || len(opts.TraceSyscalls) != 1 || !opts.TraceSyscalls[want] {
		t.Fatalf("trace selector = names:%v regexps:%v, want only syscall 42 (%s)", opts.TraceSyscalls, opts.TraceSyscallRegexps, want)
	}
}

func TestParseTraceAllAndNone(t *testing.T) {
	all := ParseArgs([]string{"--trace=all", "/bin/true"})
	if !all.TraceConfigured || !all.TraceMatchesAll {
		t.Fatalf("trace=all state = configured:%v all:%v", all.TraceConfigured, all.TraceMatchesAll)
	}
	allWithName := ParseArgs([]string{"--trace=all,read", "/bin/true"})
	if !allWithName.TraceMatchesAll {
		t.Fatal("trace=all,read should retain universal-set semantics")
	}

	none := ParseArgs([]string{"--trace=!all", "/bin/true"})
	if !none.TraceConfigured || none.TraceMatchesAll || none.TraceSetIsNegated || len(none.TraceSyscalls) != 0 {
		t.Fatalf("trace=!all state = configured:%v all:%v negated:%v names:%v", none.TraceConfigured, none.TraceMatchesAll, none.TraceSetIsNegated, none.TraceSyscalls)
	}
}

func TestParseSyscallFormattingSelectors(t *testing.T) {
	opts := ParseArgs([]string{
		"--abbrev=execve",
		"--raw=!chdir",
		"--verbose=!execve",
		"/bin/true",
	})

	if opts.NoAbbrevFor("execve") || !opts.NoAbbrevFor("chdir") {
		t.Fatalf("abbrev selector mismatch: execve=%v chdir=%v", opts.NoAbbrevFor("execve"), opts.NoAbbrevFor("chdir"))
	}
	if !opts.RawSyscallFor("execve") || opts.RawSyscallFor("chdir") {
		t.Fatalf("raw selector mismatch: execve=%v chdir=%v", opts.RawSyscallFor("execve"), opts.RawSyscallFor("chdir"))
	}
	if opts.VerboseDecodeFor("execve") || !opts.VerboseDecodeFor("chdir") {
		t.Fatalf("verbose selector mismatch: execve=%v chdir=%v", opts.VerboseDecodeFor("execve"), opts.VerboseDecodeFor("chdir"))
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

func TestParseReadWriteAllFDsFromEFlag(t *testing.T) {
	opts := ParseArgs([]string{"-eread=all", "-e", "write=!none", "/bin/true"})

	if !opts.TraceReadFD(0) || !opts.TraceReadFD(65535) {
		t.Fatalf("TraceReadFD did not match all fds: %#v", opts.TraceReadFDs)
	}
	if !opts.TraceWriteFD(1) || !opts.TraceWriteFD(65536) {
		t.Fatalf("TraceWriteFD did not match all fds: %#v", opts.TraceWriteFDs)
	}
	if !opts.TraceReadFDs[TraceAllFDs] || !opts.TraceWriteFDs[TraceAllFDs] {
		t.Fatalf("all-fd sentinel missing: read=%#v write=%#v", opts.TraceReadFDs, opts.TraceWriteFDs)
	}
}

func TestParseReadWriteNumericFDsFromEFlag(t *testing.T) {
	opts := ParseArgs([]string{"-e", "read=0,5", "-ewrite=1,4", "/bin/true"})

	if !opts.TraceReadFD(0) || !opts.TraceReadFD(5) || opts.TraceReadFD(6) {
		t.Fatalf("TraceReadFD numeric set mismatch: %#v", opts.TraceReadFDs)
	}
	if !opts.TraceWriteFD(1) || !opts.TraceWriteFD(4) || opts.TraceWriteFD(5) {
		t.Fatalf("TraceWriteFD numeric set mismatch: %#v", opts.TraceWriteFDs)
	}
}

func TestParseReadWriteNegatedFDsFromEFlag(t *testing.T) {
	opts := ParseArgs([]string{"-eread=none", "-ewrite=!all", "-eread=!0,1,2", "-ewrite=!0,1,2", "/bin/true"})

	if opts.TraceReadFD(0) || opts.TraceReadFD(1) || opts.TraceReadFD(2) || !opts.TraceReadFD(65535) {
		t.Fatalf("TraceReadFD negated set mismatch: negated=%v set=%#v", opts.TraceReadFDsNegated, opts.TraceReadFDs)
	}
	if opts.TraceWriteFD(0) || opts.TraceWriteFD(1) || opts.TraceWriteFD(2) || !opts.TraceWriteFD(65536) {
		t.Fatalf("TraceWriteFD negated set mismatch: negated=%v set=%#v", opts.TraceWriteFDsNegated, opts.TraceWriteFDs)
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

func TestParseNoEventFormat(t *testing.T) {
	opts := ParseArgs([]string{"--event-format=none", "/bin/true"})

	if opts.EventFormat != EventFormatNone {
		t.Fatalf("EventFormat = %q, want %q", opts.EventFormat, EventFormatNone)
	}
}

func TestParseReaderEventFormat(t *testing.T) {
	opts := ParseArgs([]string{"--event-format=reader", "/bin/true"})

	if opts.EventFormat != EventFormatReader {
		t.Fatalf("EventFormat = %q, want %q", opts.EventFormat, EventFormatReader)
	}
}

func TestParseHandlerEventFormat(t *testing.T) {
	opts := ParseArgs([]string{"--event-format=handler", "/bin/true"})

	if opts.EventFormat != EventFormatHandler {
		t.Fatalf("EventFormat = %q, want %q", opts.EventFormat, EventFormatHandler)
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

func TestParseDebugPhasesAlias(t *testing.T) {
	opts := ParseArgs([]string{"--debug-phases", "/bin/true"})

	if opts.EventFormat != EventFormatJSON {
		t.Fatalf("EventFormat = %q, want %q", opts.EventFormat, EventFormatJSON)
	}
	if opts.DebugEvents {
		t.Fatal("DebugEvents = true, want false")
	}
	if !opts.DebugPhases {
		t.Fatal("DebugPhases = false, want true")
	}
}

func TestParseStackTraceLongFlag(t *testing.T) {
	opts := ParseArgs([]string{"--stack-trace", "/bin/true"})

	if !opts.StackTrace {
		t.Fatal("StackTrace = false, want true for --stack-trace")
	}
	if len(opts.CmdArgs) != 1 || opts.CmdArgs[0] != "/bin/true" {
		t.Fatalf("CmdArgs = %#v, want /bin/true", opts.CmdArgs)
	}
}

func TestParseDecodeFDsLongFlags(t *testing.T) {
	tests := []struct {
		flag string
		mode int
	}{
		{flag: "--decode-fds", mode: 1},
		{flag: "--decode-fds=path", mode: 1},
		{flag: "--decode-fds=all", mode: 2},
	}

	for _, test := range tests {
		t.Run(test.flag, func(t *testing.T) {
			opts := ParseArgs([]string{test.flag, "/bin/true"})
			if !opts.ShowPaths || opts.ShowPathsMode != test.mode {
				t.Fatalf("decode fds = enabled:%v mode:%d, want true/%d", opts.ShowPaths, opts.ShowPathsMode, test.mode)
			}
		})
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

func TestParseInvalidOptionRejected(t *testing.T) {
	if os.Getenv("STRACE_GO_PARSE_INVALID_EXIT") == "1" {
		ParseArgs([]string{"--definitely-unknown", "/bin/true"})
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestParseInvalidOptionRejected")
	cmd.Env = append(os.Environ(), "STRACE_GO_PARSE_INVALID_EXIT=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("ParseArgs(unknown) exit = %v, want status 1; stderr=%q", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "unrecognized option '--definitely-unknown'") {
		t.Fatalf("stderr = %q, want unrecognized option diagnostic", stderr.String())
	}
}

func TestParseInvalidValueRejected(t *testing.T) {
	caseID := os.Getenv("STRACE_GO_PARSE_INVALID_VALUE")
	if caseID != "" {
		argsByCase := map[string][]string{
			"columns": {"--columns=-1", "/bin/true"},
			"limit":   {"--string-limit=-1", "/bin/true"},
			"xlat":    {"--const-print-style=test", "/bin/true"},
			"missing": {"--output"},
		}
		ParseArgs(argsByCase[caseID])
		return
	}

	tests := []struct {
		name string
		want string
	}{
		{name: "columns", want: "invalid -a argument: '-1'"},
		{name: "limit", want: "invalid -s argument: '-1'"},
		{name: "xlat", want: "invalid -X argument: 'test'"},
		{name: "missing", want: "option '--output' requires an argument"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestParseInvalidValueRejected")
			cmd.Env = append(os.Environ(), "STRACE_GO_PARSE_INVALID_VALUE="+test.name)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("ParseArgs(%s) exit = %v, want status 1; stderr=%q", test.name, err, stderr.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.want)
			}
		})
	}
}
