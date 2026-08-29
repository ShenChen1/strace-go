package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestResolveNumericTraceCredential(t *testing.T) {
	credential, err := resolveTraceCredential("1000:1001", 0)
	if err != nil {
		t.Fatalf("resolveTraceCredential() error = %v", err)
	}
	if credential.Uid != 1000 || credential.Gid != 1001 || credential.Groups == nil || len(credential.Groups) != 0 {
		t.Fatalf("credential = %#v, want uid/gid 1000/1001 with cleared groups", credential)
	}
}

func TestResolveNumericTraceCredentialRejectsInvalidInput(t *testing.T) {
	for _, value := range []string{
		"1:",
		"user:2",
		"1:group",
		"1:2:3",
		"4294967295:1",
		"1:4294967295",
	} {
		_, err := resolveTraceCredential(value, 0)
		if err == nil || err.Error() != "Invalid UID:GID pair '"+value+"'" {
			t.Fatalf("resolveTraceCredential(%q) error = %v", value, err)
		}
	}
}

func TestResolveTraceCredentialRequiresRoot(t *testing.T) {
	_, err := resolveTraceCredential("1000:1001", 1000)
	if err == nil || err.Error() != "You must be root to use the -u/--username option" {
		t.Fatalf("non-root credential switch error = %v", err)
	}
}

func TestResolveTraceCredentialReportsUnknownUser(t *testing.T) {
	const name = "!strace-go-no-such-user!"
	_, err := resolveTraceCredential(name, 0)
	if err == nil || err.Error() != "Cannot find user '"+name+"'" {
		t.Fatalf("unknown user error = %v", err)
	}
}

func TestPrepareTraceTargetConfigRequiresRootBeforeBootstrap(t *testing.T) {
	targets := traceTargetConfig{command: traceCommandSpec{runAsUser: "1000:1001"}}
	if _, err := prepareTraceTargetConfig(targets, 1000); err == nil {
		t.Fatal("non-root launch authority returned nil error")
	}
	prepared, err := prepareTraceTargetConfig(targets, 0)
	if err != nil {
		t.Fatalf("root launch authority error = %v", err)
	}
	if prepared.command.credential == nil {
		t.Fatal("prepared target config is missing credential")
	}
	if _, err := prepareTraceTargetConfig(traceTargetConfig{}, 1000); err != nil {
		t.Fatalf("ordinary non-root launch authority error = %v", err)
	}
}

func TestApplyTraceCommandCredentialPreservesKillOnExit(t *testing.T) {
	cmd := newTraceCommand(traceCommandSpec{
		args:       []string{"/bin/true"},
		killOnExit: true,
	}, nil)
	credential, err := resolveTraceCredential("1000:1001", 0)
	if err != nil {
		t.Fatalf("resolveTraceCredential() error = %v", err)
	}
	if err := applyTraceCommandCredential(cmd, credential); err != nil {
		t.Fatalf("applyTraceCommandCredential() error = %v", err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != unix.SIGKILL || cmd.SysProcAttr.Credential == nil {
		t.Fatalf("SysProcAttr = %#v, want kill-on-exit and credential", cmd.SysProcAttr)
	}
}
