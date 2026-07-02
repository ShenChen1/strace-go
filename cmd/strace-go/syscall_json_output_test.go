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
	decodedWrites int
}

func newJSONOutputTestState(opts *cli.Options) *jsonOutputTestState {
	state := &jsonOutputTestState{}
	state.output = newSyscallJSONOutput(SyscallJSONOutputDeps{
		Opts: opts,
		WriteRaw: func(*bpfEvent, meta.Syscall) {
			state.rawWrites++
		},
		WriteDecoded: func(*bpfEvent, meta.Syscall, handler.Result, *handler.Context, *pendingSyscallState) {
			state.decodedWrites++
		},
	})
	return state
}

func TestSyscallJSONOutputEnterWritesRawInDebugMode(t *testing.T) {
	state := newJSONOutputTestState(&cli.Options{EventFormat: cli.EventFormatJSON, DebugEvents: true})

	state.output.HandleEnter(&bpfEvent{}, meta.Syscall{Name: "getpid"}, 101)

	if state.rawWrites != 1 {
		t.Fatalf("rawWrites = %d, want 1", state.rawWrites)
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
			got := state.output.HandleDebugRaw(&bpfEvent{}, meta.Syscall{Name: "getpid"})
			if got != tt.want {
				t.Fatalf("HandleDebugRaw() = %v, want %v", got, tt.want)
			}
			if state.rawWrites != boolInt(tt.want) {
				t.Fatalf("rawWrites = %d, want %d", state.rawWrites, boolInt(tt.want))
			}
		})
	}
}

func TestSyscallJSONOutputDecodedAppliesStatusFilterButConsumesJSON(t *testing.T) {
	state := newJSONOutputTestState(&cli.Options{EventFormat: cli.EventFormatJSON, FailedOnly: true})
	ev := syscallEventContext{
		raw:            &bpfEvent{Ret: 101},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{},
	}

	if !state.output.HandleDecoded(ev, handler.Result{}) {
		t.Fatal("JSON decoded event should be consumed even when status filter suppresses output")
	}
	if state.decodedWrites != 0 {
		t.Fatalf("decodedWrites = %d, want 0 for status-filtered success", state.decodedWrites)
	}

	ev.raw.Ret = -2
	state.output.HandleDecoded(ev, handler.Result{})
	if state.decodedWrites != 1 {
		t.Fatalf("decodedWrites = %d, want 1 for failed syscall", state.decodedWrites)
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
