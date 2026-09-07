package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestParseOptionalSyscallSelectors(t *testing.T) {
	opts := ParseArgs([]string{
		"--trace=?getpid,?not_a_syscall,?%not_a_class,?/no_match",
		"/bin/true",
	})
	if !opts.TraceSyscalls["getpid"] || len(opts.TraceSyscalls) != 1 {
		t.Fatalf("optional selector = %#v, want only getpid", opts.TraceSyscalls)
	}

	negated := ParseArgs([]string{"--trace=!?getpid", "/bin/true"})
	if !negated.TraceSetIsNegated || !negated.TraceSyscalls["getpid"] {
		t.Fatalf("negated optional selector = negated:%v names:%#v", negated.TraceSetIsNegated, negated.TraceSyscalls)
	}
}

func TestParseSyscallSelectorIgnoresEmptyListEntries(t *testing.T) {
	if os.Getenv("STRACE_GO_EMPTY_SYSCALL_SELECTOR_ENTRY") != "" {
		opts := ParseArgs([]string{"--trace=,getpid,", "/bin/true"})
		if !opts.TraceSyscalls["getpid"] || len(opts.TraceSyscalls) != 1 {
			t.Fatalf("selector = %#v, want only getpid", opts.TraceSyscalls)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestParseSyscallSelectorIgnoresEmptyListEntries")
	cmd.Env = append(os.Environ(), "STRACE_GO_EMPTY_SYSCALL_SELECTOR_ENTRY=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("selector with empty list entries failed: %v; stderr=%q", err, stderr.String())
	}
}

func TestParseSyscallPersonalitySelectors(t *testing.T) {
	caseID := os.Getenv("STRACE_GO_SYSCALL_PERSONALITY")
	native := strconv.Itoa(strconv.IntSize)
	other := "32"
	if native == other {
		other = "64"
	}
	if caseID != "" {
		value := "getpid@" + native + ",%process@" + native
		if caseID == "inactive" {
			value = "getpid@" + other
		}
		opts := ParseArgs([]string{"--trace=" + value, "/bin/true"})
		if caseID == "active" && (!opts.TraceSyscalls["getpid"] || !opts.TraceSyscalls["execve"]) {
			t.Fatalf("active personality selector = %#v", opts.TraceSyscalls)
		}
		if caseID == "inactive" && len(opts.TraceSyscalls) != 0 {
			t.Fatalf("inactive personality selector = %#v, want empty", opts.TraceSyscalls)
		}
		return
	}

	for _, caseID := range []string{"active", "inactive"} {
		t.Run(caseID, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestParseSyscallPersonalitySelectors")
			cmd.Env = append(os.Environ(), "STRACE_GO_SYSCALL_PERSONALITY="+caseID)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("personality selector %s failed: %v; stderr=%q", caseID, err, stderr.String())
			}
		})
	}
}

func TestParseSyscallPersonalitySelectorMarksStrictUnknowns(t *testing.T) {
	qualified := ParseArgs([]string{"--trace=getpid@64", "/bin/true"})
	if !qualified.TracePersonalityQualified {
		t.Fatal("qualified trace selector did not enable strict unknown filtering")
	}

	plain := ParseArgs([]string{"--trace=getpid", "/bin/true"})
	if plain.TracePersonalityQualified {
		t.Fatal("plain trace selector unexpectedly enabled strict unknown filtering")
	}
}

func TestInvalidSyscallSelectorsRejected(t *testing.T) {
	caseID := os.Getenv("STRACE_GO_INVALID_SYSCALL_SELECTOR")
	if caseID != "" {
		argsByCase := map[string][]string{
			"name":         {"--trace=not_a_syscall", "/bin/true"},
			"number":       {"--trace=32767", "/bin/true"},
			"class":        {"--trace=%not_a_class", "/bin/true"},
			"empty":        {"--trace=,", "/bin/true"},
			"no_match":     {"--trace=/no_match", "/bin/true"},
			"regexp":       {"--trace=/+id", "/bin/true"},
			"regexp_brace": {"--trace=/{id", "/bin/true"},
			"personality":  {"--trace=getpid@bad", "/bin/true"},
			"qualified":    {"--trace=not_a_syscall@64", "/bin/true"},
			"inject_short": {"-einject=not_a_syscall:error=EIO", "/bin/true"},
			"fault_long":   {"--fault=not_a_syscall", "/bin/true"},
		}
		ParseArgs(argsByCase[caseID])
		return
	}

	tests := []struct {
		name string
		want string
	}{
		{name: "name", want: "invalid system call 'not_a_syscall'"},
		{name: "number", want: "invalid system call '32767'"},
		{name: "class", want: "invalid system call '%not_a_class'"},
		{name: "empty", want: "invalid system call ','"},
		{name: "no_match", want: "invalid system call '/no_match'"},
		{name: "regexp", want: "regcomp: +id:"},
		{name: "regexp_brace", want: "regcomp: {id:"},
		{name: "personality", want: "incorrect personality designator 'bad' in qualification 'getpid@bad'"},
		{name: "qualified", want: "invalid system call 'not_a_syscall@64'"},
		{name: "inject_short", want: "invalid system call 'not_a_syscall'"},
		{name: "fault_long", want: "invalid system call 'not_a_syscall'"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestInvalidSyscallSelectorsRejected")
			cmd.Env = append(os.Environ(), "STRACE_GO_INVALID_SYSCALL_SELECTOR="+test.name)
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
