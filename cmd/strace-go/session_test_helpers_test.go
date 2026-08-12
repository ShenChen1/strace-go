package main

import (
	"io"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func newTimeFormatter(bootTimeOffsetNs int64) *TimeFormatter {
	return newTimeFormatterWithClock(bootTimeOffsetNs, systemTraceClock{})
}

func calculateTimeOffset() int64 {
	return calculateTimeOffsetWithClock(systemTraceClock{})
}

func newTestTraceSession(deps traceSessionDeps) *traceSession {
	deps = withTestTraceSessionDefaults(deps)
	session, err := newTraceSession(deps)
	if err != nil {
		panic(err)
	}
	return session
}

func newBareTestTraceSession(deps traceSessionDeps) *traceSession {
	deps = withTestTraceSessionDefaults(deps)
	return &traceSession{
		dependencies: deps,
		eventPolicy:  deps.EventPolicy,
	}
}

func withTestTraceSessionDefaults(deps traceSessionDeps) traceSessionDeps {
	if deps.Events == nil {
		deps.Events = &fakeRingbufReader{}
	}
	if deps.EventPolicy == nil {
		deps.EventPolicy = newTraceEventPolicy(&cli.Options{})
	}
	if deps.OutputPolicy == nil {
		deps.OutputPolicy = newTraceOutputPolicy(&cli.Options{})
	}
	if deps.Catalog == nil {
		deps.Catalog = meta.NewCatalog("abbrev")
	}
	if deps.Decoder == nil {
		deps.Decoder = event.NewDecoder()
	}
	if deps.FDState == nil {
		deps.FDState = newFDStateStoreFromMaps(nil, nil)
	}
	if deps.Runtime == nil {
		deps.Runtime = handler.NewRuntime()
	}
	if deps.OutWriter == nil {
		deps.OutWriter = io.Discard
	}
	if deps.Summary == nil {
		deps.Summary = newSummaryStats()
	}
	if deps.Clock == nil {
		deps.Clock = systemTraceClock{}
	}
	if deps.PIDProbe == nil {
		deps.PIDProbe = systemTracePIDProbe{}
	}
	if deps.TimeFormatter == nil {
		deps.TimeFormatter = newTimeFormatterWithClock(0, deps.Clock)
	}
	if deps.State == nil {
		deps.State = newTraceStateForSession(deps.EventPolicy)
	}
	return deps
}

func testTraceSessionDeps(opts *cli.Options, deps traceSessionDeps) traceSessionDeps {
	if opts == nil {
		opts = &cli.Options{}
	}
	deps.EventPolicy = newTraceEventPolicy(opts)
	deps.OutputPolicy = newTraceOutputPolicy(opts)
	return deps
}

func newTestTraceSessionWithOptions(opts *cli.Options, deps traceSessionDeps) *traceSession {
	return newTestTraceSession(testTraceSessionDeps(opts, deps))
}

func newBareTestTraceSessionWithOptions(opts *cli.Options, deps traceSessionDeps) *traceSession {
	return newBareTestTraceSession(testTraceSessionDeps(opts, deps))
}
