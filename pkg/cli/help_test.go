package cli

import (
	"strings"
	"testing"
)

func TestHelpTextMatchesUpstreamWhitespaceContract(t *testing.T) {
	if !strings.Contains(HelpText, "  -N, --arg-names\n\t\t print syscall argument names\n") {
		t.Fatal("-N help indentation does not match upstream")
	}
	const upstreamSummaryColumnsLine = "                 list of time-percent, total-time, min-time, max-time, "
	for _, line := range strings.Split(HelpText, "\n") {
		if strings.HasSuffix(line, " ") && line != upstreamSummaryColumnsLine {
			t.Fatalf("help line has trailing whitespace: %q", line)
		}
	}
	if !strings.Contains(HelpText, upstreamSummaryColumnsLine+"\n") {
		t.Fatal("summary columns help line does not match upstream")
	}
}
