package main

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
	"strace-go/pkg/stacktrace"
)

func TestInstructionPointerEnablesStackCaptureAndResolver(t *testing.T) {
	opts := &cli.Options{InstructionPointer: true}
	if !newTraceBPFConfig(opts).captureStack {
		t.Fatal("instruction pointer did not enable BPF stack capture")
	}
	if newTraceSessionConfig(opts).resolver == nil {
		t.Fatal("instruction pointer did not create address resolver")
	}
}

func TestInstructionPointerPolicySnapshotsCLIState(t *testing.T) {
	opts := &cli.Options{InstructionPointer: true}
	policy := newTraceOutputPolicy(opts)
	opts.InstructionPointer = false
	if !policy.RenderOptions().instructionPointer {
		t.Fatal("instruction pointer policy changed after snapshot")
	}
}

func TestTextRendererPrintsSyscallInstructionPointer(t *testing.T) {
	var output strings.Builder
	opts := &cli.Options{InstructionPointer: true}
	renderer := newTextRenderer(TextRendererDeps{
		Out:         &output,
		Policy:      newTraceOutputPolicy(opts),
		StackTraces: &fakeTraceStackTraceReader{ips: [127]uint64{0x1234}},
		Resolver:    stacktrace.NewResolver(),
	})
	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 0, stackID: 7},
		meta:           meta.Syscall{Name: "getpid"},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	wantPrefix := fmt.Sprintf("[%0*x] getpid", strconv.IntSize/4, uint64(0x1234))
	if !strings.HasPrefix(output.String(), wantPrefix) {
		t.Fatalf("renderer output = %q, want prefix %q", output.String(), wantPrefix)
	}
}

func TestSignalInstructionPointerFlowsFromABIToRenderer(t *testing.T) {
	raw := traceEventV2SignalSample(traceEventV2SampleSpec{signal: 11})
	body := raw[traceEventV2HeaderLen:]
	binary.LittleEndian.PutUint32(body[traceEventV2SignalStackIDOffset:], uint32(7))
	envelope, ok := decodeTraceEventV2Envelope(raw)
	if !ok || envelope.stackID != 7 || envelope.signalView().stackID != 7 {
		t.Fatalf("signal envelope = %+v, want stack id 7", envelope)
	}

	var output strings.Builder
	renderer := newTextRenderer(TextRendererDeps{
		Out:         &output,
		Policy:      newTraceOutputPolicy(&cli.Options{InstructionPointer: true}),
		StackTraces: &fakeTraceStackTraceReader{ips: [127]uint64{0x5678}},
		Resolver:    stacktrace.NewResolver(),
	})
	renderer.PrintSignalEvent(envelope.signalView(), "SIGSEGV")
	wantPrefix := fmt.Sprintf("[%0*x] --- SIGSEGV", strconv.IntSize/4, uint64(0x5678))
	if !strings.HasPrefix(output.String(), wantPrefix) {
		t.Fatalf("signal output = %q, want prefix %q", output.String(), wantPrefix)
	}
}

func TestInstructionPointerUsesUpstreamForkPIDPrefixes(t *testing.T) {
	opts := &cli.Options{FollowForks: true, InstructionPointer: true}
	renderer := newTextRenderer(TextRendererDeps{
		Policy:    newTraceOutputPolicy(opts),
		TargetPID: 101,
	})
	unknown := "[" + strings.Repeat("?", strconv.IntSize/4) + "] "

	if got, want := renderer.ExitStatusLine(101, 0), unknown+"+++ exited with 0 +++\n"; got != want {
		t.Fatalf("target exit line = %q, want %q", got, want)
	}
	if got, want := renderer.LifecycleExitStatusLine(202, uint64(11)),
		fmt.Sprintf("[pid %5d] %s+++ killed by SIGSEGV +++\n", 202, unknown); got != want {
		t.Fatalf("child signal exit line = %q, want %q", got, want)
	}
}

func TestInstructionPointerPrefixesResumedSyscall(t *testing.T) {
	var output strings.Builder
	opts := &cli.Options{InstructionPointer: true}
	renderer := newTextRenderer(TextRendererDeps{
		Out:         &output,
		Policy:      newTraceOutputPolicy(opts),
		StackTraces: &fakeTraceStackTraceReader{ips: [127]uint64{0x9876}},
	})
	renderer.PrintSyscallEvent(syscallEventContext{
		view:           syscallEventView{valid: true, tid: 101, ret: 0, stackID: 7},
		meta:           meta.Syscall{Name: "read"},
		pendingEnter:   &pendingSyscallSnapshot{unfinishedPrinted: true},
		handlerContext: &handler.Context{Opts: opts},
	}, handler.Result{})

	wantPrefix := fmt.Sprintf("[%0*x] <... read resumed>)", strconv.IntSize/4, uint64(0x9876))
	if !strings.HasPrefix(output.String(), wantPrefix) {
		t.Fatalf("resumed output = %q, want prefix %q", output.String(), wantPrefix)
	}
}

func TestInstructionPointerRendersFaultSignalDetails(t *testing.T) {
	var output strings.Builder
	renderer := newTextRenderer(TextRendererDeps{
		Out:    &output,
		Policy: newTraceOutputPolicy(&cli.Options{InstructionPointer: true}),
	})
	renderer.PrintSignalEvent(signalEventView{
		tid:     101,
		signo:   11,
		code:    1,
		address: 0x1234,
		stackID: -1,
	}, "SIGSEGV")

	unknown := "[" + strings.Repeat("?", strconv.IntSize/4) + "] "
	want := unknown + "--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x1234} ---\n"
	if got := output.String(); got != want {
		t.Fatalf("fault signal output = %q, want %q", got, want)
	}
}

func TestInstructionPointerRendersChildSignalIdentity(t *testing.T) {
	var output strings.Builder
	renderer := newTextRenderer(TextRendererDeps{
		Out:    &output,
		Policy: newTraceOutputPolicy(&cli.Options{InstructionPointer: true}),
	})
	renderer.PrintSignalEvent(signalEventView{
		tid:       101,
		signo:     17,
		code:      3,
		senderPID: 202,
		senderUID: 1000,
		stackID:   -1,
	}, "SIGCHLD")

	wantFragment := "si_code=CLD_DUMPED, si_pid=202, si_uid=1000"
	if got := output.String(); !strings.Contains(got, wantFragment) {
		t.Fatalf("child signal output = %q, want fragment %q", got, wantFragment)
	}
}

func TestInstructionPointerUsesUnknownPrefixWithoutStack(t *testing.T) {
	renderer := newTextRenderer(TextRendererDeps{
		Policy: newTraceOutputPolicy(&cli.Options{InstructionPointer: true}),
	})
	want := "[" + strings.Repeat("?", strconv.IntSize/4) + "] +++ exited with 0 +++\n"
	if got := renderer.ExitStatusLine(101, 0); got != want {
		t.Fatalf("exit line = %q, want %q", got, want)
	}
}
