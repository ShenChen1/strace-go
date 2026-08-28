package main

type traceSyscallLimitObserver interface {
	Observe(syscallEventContext)
}

// traceSyscallLimit is session-owned mutable state. It observes only completed
// syscalls that survive the same output filters used by upstream strace.
type traceSyscallLimit struct {
	remaining uint64
	enabled   bool
	policy    traceEventOutputPolicy
}

var _ traceSyscallLimitObserver = (*traceSyscallLimit)(nil)

func newTraceSyscallLimit(limit uint64, policy traceEventOutputPolicy) *traceSyscallLimit {
	return &traceSyscallLimit{
		remaining: limit,
		enabled:   limit > 0,
		policy:    policy,
	}
}

func (l *traceSyscallLimit) Observe(ev syscallEventContext) {
	if l == nil || !l.enabled || l.remaining == 0 || !ev.shouldOutput() {
		return
	}
	if l.policy != nil && !l.policy.ShouldEmit(ev, false) {
		return
	}
	l.remaining--
}

func (l *traceSyscallLimit) Enabled() bool {
	return l != nil && l.enabled
}

func (l *traceSyscallLimit) Reached() bool {
	return l != nil && l.enabled && l.remaining == 0
}

func (l *traceSyscallLimit) Remaining() uint64 {
	if l == nil {
		return 0
	}
	return l.remaining
}
