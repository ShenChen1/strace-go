package main

import (
	"io"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
	"strace-go/pkg/meta"
)

func newTestTraceSession(deps traceSessionDeps) *traceSession {
	if deps.Events == nil {
		deps.Events = &fakeRingbufReader{}
	}
	if deps.Opts == nil {
		deps.Opts = &cli.Options{}
	}
	if deps.Catalog == nil {
		format := deps.Opts.XlatFormat
		if format == "" {
			format = "abbrev"
		}
		deps.Catalog = meta.NewCatalog(format)
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
	if deps.TimeFormatter == nil {
		deps.TimeFormatter = newTimeFormatterWithClock(0, deps.Clock)
	}
	if deps.State == nil {
		deps.State = newTraceStateForSession(deps.Opts)
	}

	session, err := newTraceSession(deps)
	if err != nil {
		panic(err)
	}
	return session
}
