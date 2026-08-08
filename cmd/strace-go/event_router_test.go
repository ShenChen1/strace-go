package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

type fakeRouterExitEffects struct {
	recorded []syscallEventContext
}

func (e *fakeRouterExitEffects) RecordSummary(ev syscallEventContext) {
	e.recorded = append(e.recorded, ev)
}

func (e *fakeRouterExitEffects) UpdateFDOffsets(syscallEventContext) {}

func (e *fakeRouterExitEffects) CleanupClosedFD(syscallEventContext) {}

func TestTraceEventRouterSkipsOutOfScopeEvents(t *testing.T) {
	state := newTraceState()
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(100, nil),
		TargetPID: 100,
		State:     state,
	})

	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        200,
		tid:        200,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})

	if len(state.pendingSyscalls) != 0 {
		t.Fatalf("pending syscalls = %d, want no out-of-scope state update", len(state.pendingSyscalls))
	}
}

func TestTraceEventRouterRoutesLifecycleEvents(t *testing.T) {
	effects := &fakeLifecycleEffects{}
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(100, nil),
		TargetPID: 100,
		State:     newTraceState(),
		Lifecycle: newLifecycleEventHandler(LifecycleEventHandlerDeps{
			Effects: effects,
		}),
	})

	router.Handle(traceEventEnvelope{
		valid:           true,
		pid:             100,
		tid:             101,
		eventType:       bpfEventTypeLifecycle,
		lifecycleAction: lifecycleFork,
		args:            [6]uint64{100, 101},
	})

	if len(effects.inherited) != 1 || effects.inherited[0] != [2]int{100, 101} {
		t.Fatalf("inherited = %v, want [100 101]", effects.inherited)
	}
}

func TestTraceEventRouterRoutesGenericEnterToJSON(t *testing.T) {
	opts := cli.ParseArgs([]string{"--event-format=json", "--debug-events", "/bin/true"})
	rawEvents := 0
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(100, opts),
		TargetPID: 100,
		State:     newTraceState(),
		JSON: newSyscallJSONOutput(SyscallJSONOutputDeps{
			Opts: opts,
			Writer: &fakeJSONEventWriter{
				onRaw: func(syscallEventContext) {
					rawEvents++
				},
			},
		}),
	})

	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        100,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})

	if rawEvents != 1 {
		t.Fatalf("rawEvents = %d, want one generic enter JSON event", rawEvents)
	}
	if got := len(router.traceState().pendingSyscalls); got != 1 {
		t.Fatalf("pending syscalls = %d, want generic enter cached", got)
	}
}

func TestTraceEventRouterRoutesExitToPipeline(t *testing.T) {
	opts := &cli.Options{SummaryOnly: true}
	effects := &fakeRouterExitEffects{}
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(100, opts),
		TargetPID: 100,
		State:     newTraceState(),
		Pipeline: newSyscallExitPipeline(SyscallExitPipelineDeps{
			Opts:    opts,
			Effects: effects,
		}),
		ContextDeps: syscallEventContextDeps{
			decoder: event.NewDecoder(),
			opts:    opts,
			fdState: newFDStateStoreFromMaps(nil, nil),
		},
	})

	router.Handle(traceEventEnvelope{
		valid:     true,
		pid:       100,
		tid:       100,
		sysID:     syscallIDByName(t, "getpid"),
		eventType: bpfEventTypeExit,
		ret:       100,
	})

	if len(effects.recorded) != 1 {
		t.Fatalf("recorded = %d, want one exit pipeline record", len(effects.recorded))
	}
	if got := effects.recorded[0].syscallName(); got != "getpid" {
		t.Fatalf("recorded syscall = %q, want getpid", got)
	}
}

var _ SyscallExitEffects = (*fakeRouterExitEffects)(nil)
var _ LifecycleEffects = (*fakeLifecycleEffects)(nil)
