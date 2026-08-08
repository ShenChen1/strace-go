package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
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

func TestTraceEventRouterPrintsGenericUnfinishedBeforeOtherTIDEvent(t *testing.T) {
	opts := &cli.Options{EventFormat: cli.EventFormatText, FollowForks: true}
	state := newTraceState()
	var output bytes.Buffer
	renderer := newTextRenderer(TextRendererDeps{
		Out:           &output,
		Opts:          opts,
		State:         state,
		TimeFormatter: newTimeFormatter(0),
	})
	textOutput := newSyscallTextOutput(SyscallTextOutputDeps{
		Opts:     opts,
		Renderer: renderer,
	})
	runner := newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
		HandleSyscall: func(name string, _ *handler.Context) handler.Result {
			if name == "read" {
				return handler.Result{ArgParts: []string{"3", "\"\"", "4"}}
			}
			return handler.Result{}
		},
	})
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(100, opts),
		TargetPID: 100,
		State:     state,
		Pipeline: newSyscallExitPipeline(SyscallExitPipelineDeps{
			Opts:   opts,
			Runner: runner,
			Text:   textOutput,
		}),
		ContextDeps: syscallEventContextDeps{
			decoder: event.NewDecoder(),
			opts:    opts,
			fdState: newFDStateStoreFromMaps(nil, nil),
		},
	})

	readID := syscallIDByName(t, "read")
	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        101,
		sysID:      readID,
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		args:       [6]uint64{3, 0x2000, 4},
		enterTime:  10,
	})
	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        100,
		tid:        102,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
		enterTime:  20,
	})

	if !bytes.Contains(output.Bytes(), []byte("101   read(3, \"\", 4 <unfinished ...>")) {
		t.Fatalf("output after other TID enter = %q, want read unfinished line", output.String())
	}

	router.Handle(traceEventEnvelope{
		valid:     true,
		pid:       100,
		tid:       101,
		sysID:     readID,
		eventType: bpfEventTypeExit,
		ret:       4,
		duration:  5,
	})
	if !bytes.Contains(output.Bytes(), []byte("101   <... read resumed>) = 4")) {
		t.Fatalf("output after read exit = %q, want read resumed line", output.String())
	}
}

var _ SyscallExitEffects = (*fakeRouterExitEffects)(nil)
var _ LifecycleEffects = (*fakeLifecycleEffects)(nil)
