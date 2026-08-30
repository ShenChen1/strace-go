package handler

import (
	"testing"

	"strace-go/pkg/cli"
)

type optionsPortTestStub struct {
	stringLimit     int
	escapeMode      int
	verbose         bool
	verboseDisabled bool
	showPaths       bool
	showPathsMode   int
	showFDPath      bool
	showFDDevice    bool
	showFDEventFD   bool
	showFDPIDFD     bool
	showFDSignalFD  bool
	showFDSocket    bool
	traceRead       bool
	traceWrite      bool
}

func (stub optionsPortTestStub) StringLimitValue() int {
	return stub.stringLimit
}

func (stub optionsPortTestStub) HexEscapeModeValue() int {
	return stub.escapeMode
}

func (stub optionsPortTestStub) VerboseValue() bool {
	return stub.verbose
}

func (stub optionsPortTestStub) VerboseDisabledFor(string) bool {
	return stub.verboseDisabled
}

func (stub optionsPortTestStub) NoAbbrevFor(string) bool {
	return stub.verbose
}

func (stub optionsPortTestStub) VerboseDecodeFor(string) bool {
	return !stub.verboseDisabled
}

func (stub optionsPortTestStub) RawSyscallFor(string) bool {
	return false
}

func (stub optionsPortTestStub) ShowPathsValue() bool {
	return stub.showPaths
}

func (stub optionsPortTestStub) ShowPathsModeValue() int {
	return stub.showPathsMode
}

func (stub optionsPortTestStub) ShowFDPathValue() bool { return stub.showFDPath }

func (stub optionsPortTestStub) ShowFDDeviceValue() bool { return stub.showFDDevice }

func (stub optionsPortTestStub) ShowFDEventFDValue() bool { return stub.showFDEventFD }

func (stub optionsPortTestStub) ShowFDPIDFDValue() bool { return stub.showFDPIDFD }

func (stub optionsPortTestStub) ShowFDSignalFDValue() bool { return stub.showFDSignalFD }

func (stub optionsPortTestStub) ShowFDSocketValue() bool { return stub.showFDSocket }

func (stub optionsPortTestStub) TraceReadFD(int32) bool {
	return stub.traceRead
}

func (stub optionsPortTestStub) TraceWriteFD(int32) bool {
	return stub.traceWrite
}

var _ OptionsPort = optionsPortTestStub{}

func cliOptionsForTest(ctx *Context) *cli.Options {
	options, ok := ctx.Opts.(*cli.Options)
	if !ok || options == nil {
		panic("handler test requires *cli.Options as the options owner")
	}
	return options
}

func TestHandlersAcceptOptionsPort(t *testing.T) {
	ctx := &Context{Opts: optionsPortTestStub{stringLimit: 3}}
	if got := pollDisplayLimit(ctx); got != 3 {
		t.Fatalf("pollDisplayLimit with an options port = %d, want 3", got)
	}

	ctx.Opts = optionsPortTestStub{verbose: true}
	want := pollPayloadLimit / pollFdSize
	if got := pollDisplayLimit(ctx); got != want {
		t.Fatalf("verbose pollDisplayLimit with an options port = %d, want %d", got, want)
	}
}
