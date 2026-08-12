package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

type fakeTraceFormatPolicy struct{ json bool }

func (p fakeTraceFormatPolicy) IsJSON() bool { return p.json }

type fakeTraceEventOutputPolicy struct {
	debug bool
	emit  bool
}

func (p fakeTraceEventOutputPolicy) DebugEvents() bool { return p.debug }

func (p fakeTraceEventOutputPolicy) ShouldEmit(syscallEventContext, bool) bool {
	return p.emit
}

type fakeTraceSummaryPolicy struct {
	only     bool
	andPrint bool
}

func (p fakeTraceSummaryPolicy) SummaryOnly() bool     { return p.only }
func (p fakeTraceSummaryPolicy) SummaryAndPrint() bool { return p.andPrint }

type fakeTraceExitPolicy struct {
	json  bool
	only  bool
	quiet bool
}

func (p fakeTraceExitPolicy) IsJSON() bool      { return p.json }
func (p fakeTraceExitPolicy) SummaryOnly() bool { return p.only }
func (p fakeTraceExitPolicy) QuietExit() bool   { return p.quiet }

var (
	_ traceFormatPolicy      = fakeTraceFormatPolicy{}
	_ traceEventOutputPolicy = fakeTraceEventOutputPolicy{}
	_ traceSummaryPolicy     = fakeTraceSummaryPolicy{}
	_ traceExitPolicy        = fakeTraceExitPolicy{}
)

func TestTraceOutputPolicySnapshotsMutableCLIState(t *testing.T) {
	opts := &cli.Options{
		EventFormat:    cli.EventFormatText,
		SuccessfulOnly: true,
		TraceStatus:    map[string]bool{"successful": true},
	}
	policy := newTraceOutputPolicy(opts)

	opts.EventFormat = cli.EventFormatJSON
	opts.SuccessfulOnly = false
	opts.FailedOnly = true
	opts.TraceStatus["successful"] = false
	opts.TraceStatus["failed"] = true

	ev := syscallEventContext{
		view: syscallEventView{
			valid:         true,
			ret:           0,
			probeRetEnter: -1,
		},
	}
	if policy.IsJSON() {
		t.Fatal("policy format changed after snapshot")
	}
	if !policy.ShouldEmit(ev, false) {
		t.Fatal("policy status changed after snapshot")
	}
}

func TestTraceOutputPolicyPortsAcceptIndependentImplementations(t *testing.T) {
	format := fakeTraceFormatPolicy{json: true}
	events := fakeTraceEventOutputPolicy{debug: true, emit: false}
	summary := fakeTraceSummaryPolicy{only: true, andPrint: false}
	exit := fakeTraceExitPolicy{json: true, only: true, quiet: true}

	if !format.IsJSON() || !events.DebugEvents() || events.ShouldEmit(syscallEventContext{}, false) {
		t.Fatal("fake format/event policy ports are not usable")
	}
	if !summary.SummaryOnly() || summary.SummaryAndPrint() {
		t.Fatal("fake summary policy port is not usable")
	}
	if !exit.IsJSON() || !exit.SummaryOnly() || !exit.QuietExit() {
		t.Fatal("fake exit policy port is not usable")
	}

	text := newSyscallTextOutput(SyscallTextOutputDeps{Format: format, Policy: events})
	if text.textMode() || text.shouldEmitEvent(syscallEventContext{}) {
		t.Fatal("text output did not consume fake format/event policy")
	}
	rawWritten := false
	jsonWriter := &fakeJSONEventWriter{onRaw: func(syscallEventContext) { rawWritten = true }}
	json := newSyscallJSONOutput(SyscallJSONOutputDeps{
		Format: format,
		Policy: events,
		Writer: jsonWriter,
	})
	if !json.HandleDebugRaw(syscallEventContext{}) || !rawWritten {
		t.Fatal("JSON output did not consume fake debug policy")
	}
	pipeline := newSyscallExitPipeline(SyscallExitPipelineDeps{Summary: summary})
	if !pipeline.recordSummaryIfNeeded(syscallEventContext{}) {
		t.Fatal("exit pipeline did not consume fake summary policy")
	}
	exitOutput := newExitSyscallOutput(ExitSyscallOutputDeps{Policy: exit})
	exitEvent := syscallEventContext{
		view: syscallEventView{valid: true, eventType: bpfEventTypeExit},
		meta: meta.Syscall{Name: "exit"},
	}
	if exitOutput.Handle(exitEvent) != true {
		t.Fatal("exit output did not consume fake exit policy")
	}
	if text == nil || json == nil || pipeline == nil || exitOutput == nil {
		t.Fatal("output components rejected independent policy ports")
	}
}
