package main

import (
	"regexp"
	"testing"

	"strace-go/pkg/cli"
)

func TestTraceEventPolicySnapshotsHandlerOptions(t *testing.T) {
	opts := testOptions()
	opts.VerboseDisabled = make(map[string]bool)
	opts.StringLimit = 17
	opts.HexEscapeMode = 2
	opts.Verbose = true
	opts.VerboseDisabled["read"] = true
	opts.ShowPaths = true
	opts.ShowPathsMode = 2
	opts.TraceReadFDs[cli.TraceAllFDs] = true
	opts.TraceWriteFDs[7] = true
	policy := newTraceEventPolicy(opts)

	delete(opts.VerboseDisabled, "read")
	opts.StringLimit = 1
	opts.Verbose = false
	opts.ShowPaths = false
	delete(opts.TraceReadFDs, cli.TraceAllFDs)
	delete(opts.TraceWriteFDs, 7)

	options := policy.handlerOptions
	if options.StringLimitValue() != 17 || options.HexEscapeModeValue() != 2 || !options.VerboseValue() {
		t.Fatalf("handler scalar snapshot changed: limit=%d escape=%d verbose=%v", options.StringLimitValue(), options.HexEscapeModeValue(), options.VerboseValue())
	}
	if !options.VerboseDisabledFor("read") || !options.ShowPathsValue() || options.ShowPathsModeValue() != 2 {
		t.Fatal("handler map/scalar snapshot changed after CLI mutation")
	}
	if !options.TraceReadFD(3) || !options.TraceWriteFD(7) || options.TraceWriteFD(8) {
		t.Fatal("handler FD snapshot changed after CLI mutation")
	}
}

func TestTraceEventPolicySnapshotsNegatedFDOptions(t *testing.T) {
	opts := testOptions()
	opts.TraceReadFDs[3] = true
	opts.TraceReadFDsNegated = true
	opts.TraceWriteFDs[cli.TraceAllFDs] = true
	opts.TraceWriteFDsNegated = true
	options := newTraceHandlerOptions(opts)

	if options.TraceReadFD(3) || !options.TraceReadFD(4) {
		t.Fatal("negated read FD snapshot has incorrect membership")
	}
	if options.TraceWriteFD(3) {
		t.Fatal("negated all write FD snapshot should reject every FD")
	}
}

func TestTraceEventPolicySnapshotsFilterState(t *testing.T) {
	opts := testOptions()
	opts.DebugEvents = true
	opts.TraceSyscalls["dup"] = true
	opts.TraceFDs[3] = true
	opts.TracePaths["/tmp/input"] = true
	opts.TraceSyscallRegexps = []*regexp.Regexp{regexp.MustCompile(`^open`)}
	policy := newTraceEventPolicy(opts)

	delete(opts.TraceSyscalls, "dup")
	delete(opts.TraceFDs, 3)
	delete(opts.TracePaths, "/tmp/input")
	opts.DebugEvents = false

	filter := policy.filter
	if !filter.DebugEvents() || !filter.MatchSyscall("dup") || !filter.MatchSyscall("openat") {
		t.Fatal("filter snapshot changed after CLI mutation")
	}
	if !filter.MatchFDs([]int32{3}) || filter.MatchFDs([]int32{4}) {
		t.Fatal("filter FD snapshot changed after CLI mutation")
	}
	if paths := filter.PathFilter(); paths == nil || !paths.Matches(`"/tmp/input"`) {
		t.Fatal("filter path snapshot changed after CLI mutation")
	}
}

func TestTraceEventPolicyIsSharedBySessionAndContext(t *testing.T) {
	session := newTestTraceSession(traceSessionDeps{Opts: &cli.Options{}})
	if session.eventPolicy == nil || session.components.eventPolicy != session.eventPolicy {
		t.Fatal("session components do not share the event policy snapshot")
	}
	deps := newSyscallEventContextDeps(session)
	if deps.handlerOpts != session.eventPolicy.handlerOptions || deps.filter != session.eventPolicy.filter {
		t.Fatal("event context does not consume the session event policy ports")
	}
}
