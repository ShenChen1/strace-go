package main

import (
	"bytes"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
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

type fakeTraceRenderPolicy struct{ options traceRenderOptions }

func (p fakeTraceRenderPolicy) RenderOptions() traceRenderOptions { return p.options }
func (p fakeTraceRenderPolicy) TimeOptions() traceTimeOptions     { return p.options.time }

type fakeTraceFollowForkPolicy struct{ follow bool }

func (p fakeTraceFollowForkPolicy) FollowForks() bool { return p.follow }

type fakeTraceLifecyclePolicy struct {
	json      bool
	attachPID int
}

func (p fakeTraceLifecyclePolicy) IsJSON() bool { return p.json }

func (p fakeTraceLifecyclePolicy) IsAttachTarget(pid int) bool {
	return pid == p.attachPID
}

type fakeTraceReadyPolicy struct {
	debug  bool
	phases bool
	attach []int
}

func (p fakeTraceReadyPolicy) DebugEvents() bool { return p.debug }
func (p fakeTraceReadyPolicy) DebugPhases() bool { return p.phases }
func (p fakeTraceReadyPolicy) AttachPIDs() []int { return append([]int(nil), p.attach...) }

var (
	_ traceFormatPolicy      = fakeTraceFormatPolicy{}
	_ traceEventOutputPolicy = fakeTraceEventOutputPolicy{}
	_ traceSummaryPolicy     = fakeTraceSummaryPolicy{}
	_ traceExitPolicy        = fakeTraceExitPolicy{}
	_ traceRenderPolicy      = fakeTraceRenderPolicy{}
	_ traceTimePolicy        = fakeTraceRenderPolicy{}
	_ traceFollowForkPolicy  = fakeTraceFollowForkPolicy{}
	_ traceLifecyclePolicy   = fakeTraceLifecyclePolicy{}
	_ traceReadyPolicy       = fakeTraceReadyPolicy{}
)

func TestTraceOutputPolicySnapshotsMutableCLIState(t *testing.T) {
	opts := &cli.Options{
		EventFormat:    cli.EventFormatText,
		SuccessfulOnly: true,
		FollowForks:    true,
		PrintTimeMode:  3,
		AttachPids:     []int{101},
		TraceStatus:    map[string]bool{"successful": true},
	}
	policy := newTraceOutputPolicy(opts)

	opts.EventFormat = cli.EventFormatJSON
	opts.SuccessfulOnly = false
	opts.FailedOnly = true
	opts.FollowForks = false
	opts.PrintTimeMode = 0
	opts.AttachPids[0] = 202
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
	options := policy.RenderOptions()
	if !options.followForks || options.time.printTimeMode != 3 {
		t.Fatalf("render policy changed after snapshot: %+v", options)
	}
	if !policy.IsAttachTarget(101) || policy.IsAttachTarget(202) {
		t.Fatal("attach target policy changed after snapshot")
	}
	attachPIDs := policy.AttachPIDs()
	attachPIDs[0] = 303
	if !policy.IsAttachTarget(101) {
		t.Fatal("attach PID policy leaked its backing slice")
	}
}

func TestTraceOutputPolicyPortsAcceptIndependentImplementations(t *testing.T) {
	format := fakeTraceFormatPolicy{json: true}
	events := fakeTraceEventOutputPolicy{debug: true, emit: false}
	summary := fakeTraceSummaryPolicy{only: true, andPrint: false}
	exit := fakeTraceExitPolicy{json: true, only: true, quiet: true}
	ready := fakeTraceReadyPolicy{debug: true, phases: true, attach: []int{42, 84}}

	if !format.IsJSON() || !events.DebugEvents() || events.ShouldEmit(syscallEventContext{}, false) {
		t.Fatal("fake format/event policy ports are not usable")
	}
	if !summary.SummaryOnly() || summary.SummaryAndPrint() {
		t.Fatal("fake summary policy port is not usable")
	}
	if !exit.IsJSON() || !exit.SummaryOnly() || !exit.QuietExit() {
		t.Fatal("fake exit policy port is not usable")
	}
	if !ready.DebugEvents() {
		t.Fatal("fake ready policy debug port is not usable")
	}
	if !ready.DebugPhases() {
		t.Fatal("fake ready policy phase port is not usable")
	}
	readyPIDs := ready.AttachPIDs()
	if len(readyPIDs) != 2 || readyPIDs[0] != 42 || readyPIDs[1] != 84 {
		t.Fatalf("fake ready policy attach PIDs = %v", readyPIDs)
	}
	readyPIDs[0] = 99
	if ready.AttachPIDs()[0] != 42 {
		t.Fatal("fake ready policy leaked its backing slice")
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

func TestTraceRenderPolicyPortsCanBeInjected(t *testing.T) {
	policy := fakeTraceRenderPolicy{options: traceRenderOptions{
		time:              traceTimeOptions{printRelativeTime: true},
		followForks:       true,
		alignCol:          40,
		printSyscallTime:  true,
		quietThreadExecve: true,
	}}
	if got := newTimeFormatter(0).Prefix(1_000_000_000, policy); got != "     0.000000 " {
		t.Fatalf("fake render time policy = %q", got)
	}

	var output bytes.Buffer
	renderer := newTextRenderer(TextRendererDeps{
		Out:           &output,
		Policy:        policy,
		State:         newTraceState(),
		TimeFormatter: newTimeFormatter(0),
	})
	renderer.PrintSyscallEvent(syscallEventContext{
		view: syscallEventView{valid: true, tid: 101, ret: 0, duration: 1_234_000},
		meta: meta.Syscall{Name: "getpid"},
	}, handler.Result{})
	got := output.String()
	if !strings.Contains(got, "     0.000000 101   getpid()") || !strings.Contains(got, "<0.001234>") {
		t.Fatalf("fake render policy output = %q", got)
	}

	execOutput := newExecSyscallOutput(ExecSyscallOutputDeps{
		Policy:   fakeTraceFollowForkPolicy{follow: true},
		Renderer: renderer,
	})
	if !execOutput.followForks() {
		t.Fatal("fake follow-forks policy was not consumed")
	}
}
