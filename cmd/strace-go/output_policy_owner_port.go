package main

// traceOutputPolicyOwner exists at the session composition boundary.
// Runtime components receive the smallest output policy port they need.
type traceOutputPolicyOwner interface {
	traceFormatPolicy
	traceEventOutputPolicy
	traceSummaryPolicy
	traceSignalOutputPolicy
	traceExitPolicy
	traceRenderPolicy
	traceTimePolicy
	traceFollowForkPolicy
	traceScopePolicy
	traceLifecyclePolicy
	traceReadyPolicy
}

var _ traceOutputPolicyOwner = (*cliTraceOutputPolicy)(nil)
