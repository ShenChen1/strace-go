package main

import (
	"bytes"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestTraceStateClassifiesSignalWithoutSyscallMutation(t *testing.T) {
	state := newTraceState()
	update := state.handleEnvelope(traceEventEnvelope{
		valid:      true,
		pid:        101,
		tid:        102,
		eventType:  bpfEventTypeSignal,
		enterTime:  900,
		signal:     2,
		signalCode: signalCodeUser,
		senderPID:  201,
		senderUID:  1000,
	})

	if update.kind != traceStateSignal {
		t.Fatalf("signal update kind = %d, want signal", update.kind)
	}
	if update.signalView.signo != 2 || update.signalView.senderPID != 201 ||
		update.signalView.senderUID != 1000 || update.signalView.enterTime != 900 {
		t.Fatalf("signal update = %+v", update.signalView)
	}
	if state.PendingStaleCount() != 0 {
		t.Fatalf("signal created %d pending syscalls", state.PendingStaleCount())
	}
}

func TestSignalOutputPolicyMatchesConfiguredSet(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		signo  uint32
		wanted bool
	}{
		{name: "default all", args: []string{"/bin/true"}, signo: 2, wanted: true},
		{name: "none", args: []string{"-e", "signal=none", "/bin/true"}, signo: 2},
		{name: "positive match", args: []string{"-e", "signal=SIGINT", "/bin/true"}, signo: 2, wanted: true},
		{name: "positive miss", args: []string{"-e", "signal=SIGINT", "/bin/true"}, signo: 15},
		{name: "negated match", args: []string{"-e", "signal=!SIGINT", "/bin/true"}, signo: 15, wanted: true},
		{name: "negated miss", args: []string{"-e", "signal=!SIGINT", "/bin/true"}, signo: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := newTraceOutputPolicy(cli.ParseArgs(test.args))
			if got := policy.ShouldEmitSignal(test.signo); got != test.wanted {
				t.Fatalf("ShouldEmitSignal(%d) = %v, want %v", test.signo, got, test.wanted)
			}
		})
	}
}

func TestSignalEventDispatchRendersExactUserSiginfo(t *testing.T) {
	var output bytes.Buffer
	options := cli.ParseArgs([]string{"-e", "signal=SIGINT", "/bin/true"})
	policy := newTraceOutputPolicy(options)
	renderer := newTextRenderer(TextRendererDeps{
		Out:    &output,
		Policy: policy,
	})
	signalOutput := newSignalEventOutput(policy, renderer, meta.NewCatalog("abbrev"))
	state := newTraceState()
	dispatcher := newTraceEventDispatcher(TraceEventDispatcherDeps{
		State:  state,
		Signal: signalOutput,
	})
	envelope := traceEventEnvelope{
		valid:      true,
		pid:        101,
		tid:        101,
		eventType:  bpfEventTypeSignal,
		signal:     2,
		signalCode: signalCodeUser,
		senderPID:  201,
		senderUID:  1000,
	}

	dispatcher.Dispatch(envelope, state.handleEnvelope(envelope))

	want := "--- SIGINT {si_signo=SIGINT, si_code=SI_USER, si_pid=201, si_uid=1000} ---\n"
	if got := output.String(); got != want {
		t.Fatalf("signal output = %q, want %q", got, want)
	}
}

func TestSignalEventDispatchRendersExactChildSiginfo(t *testing.T) {
	var output bytes.Buffer
	options := cli.ParseArgs([]string{"-e", "signal=SIGCHLD", "/bin/true"})
	policy := newTraceOutputPolicy(options)
	renderer := newTextRenderer(TextRendererDeps{
		Out:    &output,
		Policy: policy,
	})
	signalOutput := newSignalEventOutput(policy, renderer, meta.NewCatalog("abbrev"))
	signalOutput.HandleSignal(signalEventView{
		tid:        101,
		signo:      17,
		code:       2,
		senderPID:  201,
		senderUID:  1000,
		status:     10,
		userTime:   11,
		systemTime: 12,
	})

	want := "--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_KILLED, si_pid=201, si_uid=1000, si_status=SIGUSR1, si_utime=11, si_stime=12} ---\n"
	if got := output.String(); got != want {
		t.Fatalf("child signal output = %q, want %q", got, want)
	}
}
