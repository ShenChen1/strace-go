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
	if !strings.Contains(source, "outputPolicy       traceOutputPolicyOwner") {
		t.Fatal("session component graph still exposes concrete output policy")
	}
}

type fakeSessionOutputPolicyOwner struct{}

func (fakeSessionOutputPolicyOwner) IsJSON() bool { return false }

func (fakeSessionOutputPolicyOwner) DebugEvents() bool { return false }

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
func (fakeSessionOutputPolicyOwner) AttachPIDs() []int       { return nil }

func TestTraceSessionAcceptsOutputPolicyOwnerPort(t *testing.T) {
	owner := fakeSessionOutputPolicyOwner{}
	session := newTestTraceSession(traceSessionDeps{OutputPolicy: owner})

	if session.dependencies.OutputPolicy != owner {
		t.Fatal("session did not retain the injected output policy owner")
	}
	if session.components.outputPolicy != owner {
		t.Fatal("session components did not retain the output policy owner")
	}
	if session.textRenderer().policy != owner {
		t.Fatal("text renderer did not receive the output policy owner")
	}
	if session.syscallTextOutput().format != owner || session.syscallTextOutput().policy != owner {
		t.Fatal("syscall text output did not receive output policy projections")
	}
	if session.syscallJSONOutput().format != owner || session.syscallJSONOutput().policy != owner {
		t.Fatal("syscall JSON output did not receive output policy projections")
	}
	if session.traceRunFinalizer().formatPolicy != owner || session.traceRunFinalizer().summaryPolicy != owner {
		t.Fatal("run finalizer did not receive output policy projections")
	}
}

var _ traceOutputPolicyOwner = fakeSessionOutputPolicyOwner{}
