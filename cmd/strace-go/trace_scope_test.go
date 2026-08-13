package main

import (
	"testing"
)

type fakeTraceScopePolicy struct {
	follow bool
	attach []int
}

func (p fakeTraceScopePolicy) FollowForks() bool { return p.follow }

func (p fakeTraceScopePolicy) AttachPIDs() []int {
	return append([]int(nil), p.attach...)
}

var _ traceScopePolicy = fakeTraceScopePolicy{}

func TestTraceScopeAllowsTargetWithoutAttach(t *testing.T) {
	scope := newTraceScope(101, fakeTraceScopePolicy{})

	if !scope.AllowsPID(101) {
		t.Fatal("target pid should be allowed")
	}
	if scope.AllowsPID(0) {
		t.Fatal("zero pid should be rejected")
	}
	if scope.AllowsPID(202) {
		t.Fatal("unrelated pid should be rejected without follow-forks")
	}
}

func TestTraceScopeUsesAttachPidsAsDirectMatches(t *testing.T) {
	scope := newTraceScope(101, fakeTraceScopePolicy{attach: []int{202}})

	if !scope.AllowsPID(202) {
		t.Fatal("attached pid should be allowed")
	}
	if scope.AllowsPID(101) {
		t.Fatal("target pid should not be a direct match when attach pids are configured")
	}
}

func TestTraceScopeMatchesAttachedThreadTID(t *testing.T) {
	scope := newTraceScope(101, fakeTraceScopePolicy{attach: []int{202}})

	if !scope.AllowsEvent(100, 202) {
		t.Fatal("attached thread TID should be allowed when event PID is its TGID")
	}
	if scope.AllowsEvent(100, 303) {
		t.Fatal("unrelated thread event should be rejected without follow-forks")
	}
}

func TestTraceScopeAllowsForksWhenEnabled(t *testing.T) {
	scope := newTraceScope(101, fakeTraceScopePolicy{attach: []int{202}, follow: true})

	if !scope.AllowsPID(303) {
		t.Fatal("follow-forks should allow non-direct pids")
	}
}

func TestTraceScopeCopiesAttachPIDsFromPolicy(t *testing.T) {
	policy := &fakeTraceScopePolicy{attach: []int{202}}
	scope := newTraceScope(101, policy)
	policy.attach[0] = 303

	if !scope.AllowsPID(202) || scope.AllowsPID(303) {
		t.Fatal("scope allow rules changed after policy mutation")
	}
}
