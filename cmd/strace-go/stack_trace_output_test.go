package main

import (
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func TestStackTraceFrameLimitTruncatesSyscallOutput(t *testing.T) {
	var output strings.Builder
	opts := &cli.Options{StackTrace: true, StackFrameLimit: 2}
	renderer := newTextRenderer(TextRendererDeps{
		Out:         &output,
		Policy:      newTraceOutputPolicy(opts),
		StackTraces: stackTraceReaderWithAddresses(0x10, 0x20, 0x30),
		Resolver: fakeTextSymbolResolver{values: map[uint64]string{
			0x10: "frame_one",
			0x20: "frame_two",
			0x30: "frame_three",
		}},
	})
	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, stackID: 7},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	wantTail := " > frame_one\n > frame_two\n > too many stack frames\n"
	if !strings.HasSuffix(output.String(), wantTail) || strings.Contains(output.String(), "frame_three") {
		t.Fatalf("stack output = %q, want truncated tail %q", output.String(), wantTail)
	}
}

func TestStackTraceFrameLimitAppliesToSignalOutput(t *testing.T) {
	var output strings.Builder
	opts := &cli.Options{StackTrace: true, StackFrameLimit: 1}
	renderer := newTextRenderer(TextRendererDeps{
		Out:         &output,
		Policy:      newTraceOutputPolicy(opts),
		StackTraces: stackTraceReaderWithAddresses(0x10, 0x20),
		Resolver: fakeTextSymbolResolver{values: map[uint64]string{
			0x10: "signal_frame",
			0x20: "hidden_frame",
		}},
	})
	renderer.PrintSignalEvent(signalEventView{tid: 101, signo: 10, stackID: 7}, "SIGUSR1")

	wantTail := " > signal_frame\n > too many stack frames\n"
	if !strings.HasSuffix(output.String(), wantTail) || strings.Contains(output.String(), "hidden_frame") {
		t.Fatalf("signal stack output = %q, want truncated tail %q", output.String(), wantTail)
	}
}

func stackTraceReaderWithAddresses(addresses ...uint64) *fakeTraceStackTraceReader {
	var ips [127]uint64
	copy(ips[:], addresses)
	return &fakeTraceStackTraceReader{ips: ips}
}
