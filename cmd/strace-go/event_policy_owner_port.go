package main

import "strace-go/pkg/handler"

// traceEventPolicyOwner exists at the session composition boundary.
// Consumers receive state, handler, and filter projections separately.
type traceEventPolicyOwner interface {
	traceStatePolicy
	HandlerOptions() handler.OptionsPort
	FilterOptions() traceFilterOptions
}

var _ traceEventPolicyOwner = (*cliTraceEventPolicy)(nil)
