package main

import (
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

type jsonOutputTestState struct {
	output        *SyscallJSONOutput
	rawWrites     int
	rawView       syscallEventView
	decodedWrites int
	decodedEvent  syscallEventContext
}

func newJSONOutputTestState(opts *cli.Options) *jsonOutputTestState {
	state := &jsonOutputTestState{}
	state.output = newSyscallJSONOutput(SyscallJSONOutputDeps{
		Opts: opts,
		WriteRaw: func(ev syscallEventContext) {
			state.rawWrites++
			state.rawView = ev.eventView()
		},
		WriteDecoded: func(ev syscallEventContext, _ handler.Result) {
			state.decodedWrites++
			state.decodedEvent = ev
		},
	})
	return state
}

func TestSyscallJSONOutputEnterWritesRawInDebugMode(t *testing.T) {
	state := newJSONOutputTestState(&cli.Options{EventFormat: cli.EventFormatJSON, DebugEvents: true})

	state.output.HandleEnter(syscallEventContext{
		view:     syscallEventView{valid: true, eventType: bpfEventTypeEnter},
		meta:     meta.Syscall{Name: "getpid"},
		statePID: 101,
	})

	if state.rawWrites != 1 {
		t.Fatalf("rawWrites = %d, want 1", state.rawWrites)
	}
}

func TestSyscallJSONOutputEnterFilterUsesEventView(t *testing.T) {
	opts := testOptions()
	opts.EventFormat = cli.EventFormatJSON
	opts.TraceSyscalls["dup"] = true
	opts.TraceFDs[5] = true
	state := newJSONOutputTestState(opts)

	view := syscallEventView{valid: true, eventType: bpfEventTypeEnter, args: [6]uint64{5}}
	state.output.HandleEnter(syscallEventContext{
		view:     view,
		meta:     meta.Syscall{Name: "dup", Args: []string{"fd"}},
		statePID: 101,
	})

	if state.rawWrites != 1 {
		t.Fatalf("rawWrites = %d, want 1 from fd in event view", state.rawWrites)
	}
	if state.rawView.args[0] != 5 {
		t.Fatalf("raw view arg0 = %d, want 5 from event view", state.rawView.args[0])
	}
}

func TestSyscallJSONOutputDebugRawConsumesOnlyDebugJSON(t *testing.T) {
	tests := []struct {
		name string
		opts *cli.Options
		want bool
	}{
		{name: "text", opts: &cli.Options{EventFormat: cli.EventFormatText, DebugEvents: true}, want: false},
		{name: "json", opts: &cli.Options{EventFormat: cli.EventFormatJSON}, want: false},
		{name: "debug json", opts: &cli.Options{EventFormat: cli.EventFormatJSON, DebugEvents: true}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newJSONOutputTestState(tt.opts)
			got := state.output.HandleDebugRaw(syscallEventContext{
				view: syscallEventView{valid: true, eventType: bpfEventTypeEnter},
				meta: meta.Syscall{Name: "getpid"},
			})
			if got != tt.want {
				t.Fatalf("HandleDebugRaw() = %v, want %v", got, tt.want)
			}
			if state.rawWrites != boolInt(tt.want) {
				t.Fatalf("rawWrites = %d, want %d", state.rawWrites, boolInt(tt.want))
			}
		})
	}
}

func TestSyscallJSONOutputDebugRawUsesEventView(t *testing.T) {
	state := newJSONOutputTestState(&cli.Options{EventFormat: cli.EventFormatJSON, DebugEvents: true})
	ev := syscallEventContext{
		view: syscallEventView{valid: true, ret: -2, args: [6]uint64{7}},
		meta: meta.Syscall{Name: "getpid"},
	}

	if !state.output.HandleDebugRaw(ev) {
		t.Fatal("debug raw JSON should be consumed")
	}
	if state.rawView.ret != -2 || state.rawView.args[0] != 7 {
		t.Fatalf("raw view = %+v, want ret=-2 arg0=7", state.rawView)
	}
}

func TestSyscallJSONOutputDecodedAppliesStatusFilterButConsumesJSON(t *testing.T) {
	state := newJSONOutputTestState(&cli.Options{EventFormat: cli.EventFormatJSON, FailedOnly: true})
	ev := syscallEventContext{
		view:           syscallEventView{valid: true, eventType: bpfEventTypeExit, ret: 101},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{},
	}

	if !state.output.HandleDecoded(ev, handler.Result{}) {
		t.Fatal("JSON decoded event should be consumed even when status filter suppresses output")
	}
	if state.decodedWrites != 0 {
		t.Fatalf("decodedWrites = %d, want 0 for status-filtered success", state.decodedWrites)
	}

	failed := syscallEventContext{
		view:           syscallEventView{valid: true, eventType: bpfEventTypeExit, ret: -2},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{},
	}
	state.output.HandleDecoded(failed, handler.Result{})
	if state.decodedWrites != 1 {
		t.Fatalf("decodedWrites = %d, want 1 for failed syscall", state.decodedWrites)
	}
}

func TestSyscallJSONOutputDecodedStatusUsesEventView(t *testing.T) {
	state := newJSONOutputTestState(&cli.Options{EventFormat: cli.EventFormatJSON, FailedOnly: true})
	ev := syscallEventContext{
		view:           syscallEventView{valid: true, ret: -2},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{},
	}

	if !state.output.HandleDecoded(ev, handler.Result{}) {
		t.Fatal("JSON decoded event should be consumed")
	}
	if state.decodedWrites != 1 {
		t.Fatalf("decodedWrites = %d, want 1 from failed event view", state.decodedWrites)
	}
	if state.decodedEvent.eventView().ret != -2 {
		t.Fatalf("decoded event ret = %d, want view ret -2", state.decodedEvent.eventView().ret)
	}
}

func TestSyscallJSONOutputDecodedFallsThroughOutsideJSON(t *testing.T) {
	state := newJSONOutputTestState(&cli.Options{EventFormat: cli.EventFormatText})

	if state.output.HandleDecoded(syscallEventContext{}, handler.Result{}) {
		t.Fatal("text output should fall through decoded JSON handler")
	}
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
