package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseKVMVCPUQualifiers(t *testing.T) {
	for _, args := range [][]string{
		{"-e", "kvm=vcpu", "/bin/true"},
		{"--kvm=vcpu", "/bin/true"},
	} {
		opts := ParseArgs(args)
		if !opts.KVMExitReason {
			t.Fatalf("ParseArgs(%v) did not enable KVM exit reasons", args)
		}
		if opts.TraceConfigured {
			t.Fatalf("ParseArgs(%v) changed the syscall trace selector", args)
		}
	}
}

func TestParseKVMQualifierDiagnostics(t *testing.T) {
	caseID := os.Getenv("STRACE_GO_PARSE_KVM")
	if caseID != "" {
		argsByCase := map[string][]string{
			"invalid_e":    {"-e", "kvm=chdir"},
			"invalid_long": {"--kvm=chdir"},
			"more_e":       {"-e", "kvm=vcpu+"},
			"more_long":    {"--kvm=vcpu+"},
		}
		ParseArgs(argsByCase[caseID])
		return
	}

	tests := []struct {
		name string
		want string
	}{
		{name: "invalid_e", want: "invalid -e kvm= argument: 'chdir'"},
		{name: "invalid_long", want: "invalid -e kvm= argument: 'chdir'"},
		{name: "more_e", want: "full kvm_run decoding requires tracee mmap memory"},
		{name: "more_long", want: "full kvm_run decoding requires tracee mmap memory"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestParseKVMQualifierDiagnostics")
			cmd.Env = append(os.Environ(), "STRACE_GO_PARSE_KVM="+test.name)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("ParseArgs(%s) exit = %v, want status 1; stderr=%q", test.name, err, stderr.String())
			}
			if !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.want)
			}
		})
	}
}
