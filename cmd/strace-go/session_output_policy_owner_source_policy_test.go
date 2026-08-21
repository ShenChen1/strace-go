package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSessionUsesOutputPolicyOwnerPort(t *testing.T) {
	root := repoRootForTest(t)
	source := readTextFile(t, filepath.Join(root, "cmd", "strace-go", "session_composition.go"))
	ownerSource := readTextFile(t, filepath.Join(root, "cmd", "strace-go", "output_policy_owner_port.go"))
	if !strings.Contains(ownerSource, "type traceOutputPolicyOwner interface") {
		t.Fatal("output policy owner port is missing")
	}
	if !strings.Contains(source, "OutputPolicy  traceOutputPolicyOwner") {
		t.Fatal("traceSessionDeps must expose the output policy owner port")
	}
	if strings.Contains(source, "OutputPolicy  *cliTraceOutputPolicy") {
		t.Fatal("traceSessionDeps still exposes concrete output policy")
	}
	start := strings.Index(source, "type traceSessionComponents struct")
	if start < 0 {
		t.Fatal("traceSessionComponents definition not found")
	}
	end := strings.Index(source[start:], "\n}")
	if end < 0 {
		t.Fatal("traceSessionComponents body not found")
	}
	if strings.Contains(source[start:start+end], "outputPolicy") {
		t.Fatal("session component graph still stores a duplicate output policy owner")
	}
}

type fakeSessionOutputPolicyOwner struct {
	json       bool
	debug      bool
	phases     bool
	attachPIDs []int
}

func (p fakeSessionOutputPolicyOwner) IsJSON() bool      { return p.json }
func (fakeSessionOutputPolicyOwner) DiscardEvents() bool { return false }

func (p fakeSessionOutputPolicyOwner) DebugEvents() bool { return p.debug }
func (p fakeSessionOutputPolicyOwner) DebugPhases() bool { return p.phases }

func (fakeSessionOutputPolicyOwner) ShouldEmit(syscallEventContext, bool) bool {
	return true
}

func (fakeSessionOutputPolicyOwner) SummaryOnly() bool     { return false }
func (fakeSessionOutputPolicyOwner) SummaryAndPrint() bool { return false }
func (fakeSessionOutputPolicyOwner) QuietExit() bool       { return false }

func (fakeSessionOutputPolicyOwner) RenderOptions() traceRenderOptions {
	return traceRenderOptions{}
}

func (fakeSessionOutputPolicyOwner) TimeOptions() traceTimeOptions {
	return traceTimeOptions{}
}

func (fakeSessionOutputPolicyOwner) FollowForks() bool { return false }

func (fakeSessionOutputPolicyOwner) IsAttachTarget(int) bool { return false }
func (p fakeSessionOutputPolicyOwner) AttachPIDs() []int {
	return append([]int(nil), p.attachPIDs...)
}

func TestTraceSessionAcceptsOutputPolicyOwnerPort(t *testing.T) {
	owner := &fakeSessionOutputPolicyOwner{json: true, attachPIDs: []int{42, 84}}
	session := newTestTraceSession(traceSessionDeps{OutputPolicy: owner})

	if session.dependencies.OutputPolicy != owner {
		t.Fatal("session did not retain the injected output policy owner")
	}
	attachPIDs := session.sessionAttachPIDs()
	if len(attachPIDs) != 2 || attachPIDs[0] != 42 || attachPIDs[1] != 84 {
		t.Fatalf("session attach PIDs = %v, want [42 84]", attachPIDs)
	}
	if session.exitDrainGrace() != traceExitLifecycleDrainGrace {
		t.Fatalf("exit drain grace = %s, want %s", session.exitDrainGrace(), traceExitLifecycleDrainGrace)
	}
	if session.textRenderer().policy != owner {
		t.Fatal("text renderer did not receive the output policy owner")
	}
	if session.syscallTextOutput().format != owner || session.syscallTextOutput().policy != owner {
		t.Fatal("syscall text output did not receive output policy projections")
	}
	if !session.syscallJSONOutput().enabled || session.syscallJSONOutput().policy != owner {
		t.Fatal("syscall JSON output did not bind output policy projections")
	}
	if session.traceRunFinalizer().formatPolicy != owner || session.traceRunFinalizer().summaryPolicy != owner {
		t.Fatal("run finalizer did not receive output policy projections")
	}
}

var _ traceOutputPolicyOwner = fakeSessionOutputPolicyOwner{}
