package cli

import (
	"testing"

	"strace-go/pkg/meta"
)

func TestParseHelpSyscallGroups(t *testing.T) {
	tests := []struct {
		selector string
		flag     string
	}{
		{selector: "%clock", flag: "TCL"},
		{selector: "%fstat", flag: "TFST"},
		{selector: "%fstatfs", flag: "TFSF"},
		{selector: "%net", flag: "TN"},
		{selector: "%statfs", flag: "TSF"},
		{selector: "%%stat", flag: "TSTA"},
		{selector: "%%statfs", flag: "TSFA"},
	}

	for _, test := range tests {
		t.Run(test.selector, func(t *testing.T) {
			opts := ParseArgs([]string{"--trace=" + test.selector, "/bin/true"})
			for _, syscall := range meta.SyscallTable {
				want := syscallHasFlag(syscall.Flags, test.flag)
				if got := opts.TraceSyscalls[syscall.Name]; got != want {
					t.Fatalf("%s selects %s = %v, want %v for flags %q",
						test.selector, syscall.Name, got, want, syscall.Flags)
				}
			}
		})
	}
}
