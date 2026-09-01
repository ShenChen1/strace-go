package cli

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestParseSummarySortAndColumns(t *testing.T) {
	opts := ParseArgs([]string{"-c", "-S", "syscall_name", "-U", "count,error", "/bin/true"})

	if opts.SummarySortBy != "name" {
		t.Fatalf("SummarySortBy = %q, want name", opts.SummarySortBy)
	}
	wantColumns := []string{"calls", "errors", "name"}
	if strings.Join(opts.SummaryColumns, ",") != strings.Join(wantColumns, ",") {
		t.Fatalf("SummaryColumns = %v, want %v", opts.SummaryColumns, wantColumns)
	}
}

func TestParseSummaryLongAliases(t *testing.T) {
	opts := ParseArgs([]string{
		"--summary-only",
		"--summary-sort-by=longest",
		"--summary-columns=time,time_min,wall-avg,syscall-name",
		"/bin/true",
	})

	if opts.SummarySortBy != "max-time" {
		t.Fatalf("SummarySortBy = %q, want max-time", opts.SummarySortBy)
	}
	want := "time-percent,min-time,wall-avg,name"
	if got := strings.Join(opts.SummaryColumns, ","); got != want {
		t.Fatalf("SummaryColumns = %q, want %q", got, want)
	}
}

func TestParseInvalidSummaryOptionRejected(t *testing.T) {
	caseID := os.Getenv("STRACE_GO_INVALID_SUMMARY_OPTION")
	if caseID != "" {
		args := map[string][]string{
			"sort":      {"-c", "-S", "invalid", "/bin/true"},
			"column":    {"-c", "-U", "invalid", "/bin/true"},
			"duplicate": {"-c", "-U", "time,time_percent", "/bin/true"},
			"mode":      {"-U", "calls", "/bin/true"},
			"wall-time": {"-w", "/bin/true"},
		}
		ParseArgs(args[caseID])
		return
	}

	tests := map[string]string{
		"sort":      "invalid sortby",
		"column":    "unknown column name",
		"duplicate": "provided more than once",
		"mode":      "must be given with (-c/--summary-only or -C/--summary)",
		"wall-time": "-w/--summary-wall-clock must be given with (-c/--summary-only or -C/--summary)",
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestParseInvalidSummaryOptionRejected")
			cmd.Env = append(os.Environ(), "STRACE_GO_INVALID_SUMMARY_OPTION="+name)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr

			err := cmd.Run()
			exitErr, ok := err.(*exec.ExitError)
			if !ok || exitErr.ExitCode() != 1 {
				t.Fatalf("summary option %s exit = %v, want status 1; stderr=%q", name, err, stderr.String())
			}
			if !strings.Contains(stderr.String(), want) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), want)
			}
			if name == "wall-time" && !strings.Contains(stderr.String(), "Try '"+os.Args[0]+" -h' for more information.") {
				t.Fatalf("stderr = %q, want help hint", stderr.String())
			}
		})
	}
}
