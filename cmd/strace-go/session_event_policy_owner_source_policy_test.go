package main

import (
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/handler"
)

func TestSessionUsesEventPolicyOwnerPort(t *testing.T) {
	root := repoRootForTest(t)
	sessionSource := readTextFile(t, filepath.Join(root, "cmd", "strace-go", "session_composition.go"))
	runtimeSource := readTextFile(t, filepath.Join(root, "cmd", "strace-go", "session_runtime.go"))
	ownerSource := readTextFile(t, filepath.Join(root, "cmd", "strace-go", "event_policy_owner_port.go"))
	if !strings.Contains(ownerSource, "type traceEventPolicyOwner interface") {
		t.Fatal("event policy owner port is missing")
	}
	if !strings.Contains(sessionSource, "EventPolicy   traceEventPolicyOwner") {
		t.Fatal("traceSessionDeps must expose the event policy owner port")
	}
	if strings.Contains(sessionSource, "EventPolicy   *cliTraceEventPolicy") {
		t.Fatal("traceSessionDeps still exposes concrete event policy")
	}
	if strings.Contains(runtimeSource, "\teventPolicy") {
		t.Fatal("traceSession still stores a duplicate event policy owner")
	}
	for _, field := range []string{
		"\teventPolicy        traceEventPolicyOwner",
		"\teventPolicy     traceEventPolicyOwner",
	} {
		if strings.Contains(sessionSource, field) {
			t.Fatalf("session component graph still stores duplicate policy owner %q", field)
		}
	}
}

type fakeSessionEventPolicyOwner struct {
	handlerOptions handler.OptionsPort
	filter         traceFilterOptions
}

func (fakeSessionEventPolicyOwner) ShouldDeferUnmatchedExits() bool  { return true }
func (fakeSessionEventPolicyOwner) TrackForkIdentity() bool          { return true }
func (fakeSessionEventPolicyOwner) ElidePlainEnter() bool            { return false }
func (fakeSessionEventPolicyOwner) ElideNonBlockingPlainEnter() bool { return false }

func (p fakeSessionEventPolicyOwner) HandlerOptions() handler.OptionsPort {
	return p.handlerOptions
}

func (p fakeSessionEventPolicyOwner) FilterOptions() traceFilterOptions {
	return p.filter
}

func TestTraceSessionAcceptsEventPolicyOwnerPort(t *testing.T) {
	owner := fakeSessionEventPolicyOwner{}
	session := newTestTraceSession(traceSessionDeps{EventPolicy: owner})

	if session.dependencies.EventPolicy != owner {
		t.Fatal("session did not retain the injected event policy owner")
	}
	deps := session.eventContextDependencies()
	if deps.handlerOpts != owner.handlerOptions || deps.filter != owner.filter {
		t.Fatal("event context did not receive policy projections")
	}
}

var _ traceEventPolicyOwner = fakeSessionEventPolicyOwner{}
