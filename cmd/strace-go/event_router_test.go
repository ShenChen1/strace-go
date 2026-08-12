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
	policy := newTraceOutputPolicy(&cli.Options{FollowForks: true})
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(100, policy),
		TargetPID: 100,
		State:     newTraceState(),
		Lifecycle: newLifecycleEventHandler(LifecycleEventHandlerDeps{
			Effects: effects,
		}),
	})

	router.Handle(traceEventEnvelope{
		valid:           true,
		pid:             100,
		tid:             100,
		eventType:       bpfEventTypeLifecycle,
		lifecycleAction: lifecycleFork,
		args:            [6]uint64{100, 101},
	})

	if len(effects.inherited) != 0 {
		t.Fatalf("inherited = %v, want deferred identity resolution", effects.inherited)
	}
	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        101,
		tid:        101,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})
	if len(effects.inherited) != 1 || effects.inherited[0] != [2]int{100, 101} {
		t.Fatalf("inherited = %v, want process resolution [100 101]", effects.inherited)
	}
}

func TestTraceEventRouterDoesNotCopyFDStateForThreadClone(t *testing.T) {
	effects := &fakeLifecycleEffects{}
	state := newTraceState()
	policy := newTraceOutputPolicy(&cli.Options{FollowForks: true})
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(200, policy),
		TargetPID: 200,
		State:     state,
		Lifecycle: newLifecycleEventHandler(LifecycleEventHandlerDeps{Effects: effects}),
	})

	router.Handle(traceEventEnvelope{
		valid:           true,
		pid:             200,
		tid:             200,
		eventType:       bpfEventTypeLifecycle,
		lifecycleAction: lifecycleFork,
		args:            [6]uint64{200, 201},
	})
	router.Handle(traceEventEnvelope{
		valid:      true,
		pid:        200,
		tid:        201,
		sysID:      syscallIDByName(t, "getpid"),
		eventType:  bpfEventTypeEnter,
		eventFlags: bpfEventFlagGenericEnter,
	})

	if len(effects.inherited) != 0 {
		t.Fatalf("thread inherited = %v, want no process copy", effects.inherited)
	}
	if task := state.tasks[201]; task == nil || task.TGID != 200 {
		t.Fatalf("thread task = %+v, want TGID 200", task)
	}
}

func TestTraceEventRouterRoutesGenericEnterToJSON(t *testing.T) {
	opts := cli.ParseArgs([]string{"--event-format=json", "--debug-events", "/bin/true"})
	policy := newTraceOutputPolicy(opts)
	rawEvents := 0
	state := newTraceState()
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(100, policy),
		TargetPID: 100,
		State:     state,
		ContextDeps: syscallEventContextDeps{
			handlerOpts: opts,
			filter:      newTraceFilterOptions(opts),
		},
		JSON: newSyscallJSONOutput(SyscallJSONOutputDeps{
			Format: policy,
			Policy: policy,
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
	if got := len(state.pendingSyscalls); got != 1 {
		t.Fatalf("pending syscalls = %d, want generic enter cached", got)
	}
}

func TestTraceEventRouterRoutesExitToPipeline(t *testing.T) {
	opts := &cli.Options{SummaryOnly: true}
	policy := newTraceOutputPolicy(opts)
	effects := &fakeRouterExitEffects{}
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(100, policy),
		TargetPID: 100,
		State:     newTraceState(),
		Pipeline: newSyscallExitPipeline(SyscallExitPipelineDeps{
			Summary: policy,
			Effects: effects,
		}),
		ContextDeps: syscallEventContextDeps{
			decoder:     event.NewDecoder(),
			handlerOpts: opts,
			filter:      newTraceFilterOptions(opts),
			fdState:     newFDStateStoreFromMaps(nil, nil),
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
	policy := newTraceOutputPolicy(opts)
	state := newTraceState()
	var output bytes.Buffer
	renderer := newTextRenderer(TextRendererDeps{
		Out:           &output,
		Policy:        policy,
		State:         state,
		TimeFormatter: newTimeFormatter(0),
	})
	textOutput := newSyscallTextOutput(SyscallTextOutputDeps{
		Format:   policy,
		Policy:   policy,
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
		Scope:     newTraceScope(100, policy),
		TargetPID: 100,
		State:     state,
		Pipeline: newSyscallExitPipeline(SyscallExitPipelineDeps{
			Summary: policy,
			Runner:  runner,
			Text:    textOutput,
		}),
		ContextDeps: syscallEventContextDeps{
			decoder:     event.NewDecoder(),
			handlerOpts: opts,
			filter:      newTraceFilterOptions(opts),
			fdState:     newFDStateStoreFromMaps(nil, nil),
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

func TestTraceEventRouterDiscardsUnfinishedWithoutTextPipeline(t *testing.T) {
	state := newTraceState()
	router := newTraceEventRouter(TraceEventRouterDeps{
		Scope:     newTraceScope(100, nil),
		TargetPID: 100,
		State:     state,
		Pipeline: newSyscallExitPipeline(SyscallExitPipelineDeps{
			Runner: newSyscallHandlerRunner(SyscallHandlerRunnerDeps{
				HandleSyscall: func(string, *handler.Context) handler.Result { return handler.Result{} },
			}),
		}),
	})
	readID := syscallIDByName(t, "read")
	getpidID := syscallIDByName(t, "getpid")
	for _, event := range []traceEventEnvelope{
		{valid: true, pid: 100, tid: 101, sysID: readID, eventType: bpfEventTypeEnter, eventFlags: bpfEventFlagGenericEnter, enterTime: 10},
		{valid: true, pid: 100, tid: 102, sysID: getpidID, eventType: bpfEventTypeEnter, eventFlags: bpfEventFlagGenericEnter, enterTime: 20},
		{valid: true, pid: 100, tid: 103, sysID: getpidID, eventType: bpfEventTypeEnter, eventFlags: bpfEventFlagGenericEnter, enterTime: 30},
	} {
		router.Handle(event)
	}

	if len(state.unqueuedUnfinished) != 0 || len(state.inFlightUnfinished) != 0 {
		t.Fatalf("unfinished index = unqueued %d, in-flight %d; want empty without text output", len(state.unqueuedUnfinished), len(state.inFlightUnfinished))
	}
	if len(state.pendingSyscalls) != 3 {
		t.Fatalf("pending syscalls = %d, want all three enter events retained", len(state.pendingSyscalls))
	}
}

var _ SyscallExitEffects = (*fakeRouterExitEffects)(nil)
var _ LifecycleEffects = (*fakeLifecycleEffects)(nil)
