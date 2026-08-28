package main

import (
	"bytes"
	"strings"
	"testing"

	"strace-go/pkg/cli"
)

func TestSummaryStatsPrintsSelectedColumnsExactly(t *testing.T) {
	stats := newConfiguredSummaryStats(newSummaryOptions("name", []string{"calls", "name"}))
	stats.Record("unlinkat", 3000, -2)
	stats.Record("chdir", 1000, 0)
	stats.Record("chdir", 2000, 0)

	var output bytes.Buffer
	stats.Print(&output)
	want := "    calls syscall\n" +
		"--------- ----------------\n" +
		"        2 chdir\n" +
		"        1 unlinkat\n" +
		"--------- ----------------\n" +
		"        3 total\n"
	if output.String() != want {
		t.Fatalf("summary output:\n%s\nwant:\n%s", output.String(), want)
	}
}

func TestSummaryStatsSortsByMinimumAndMaximumDuration(t *testing.T) {
	stats := newConfiguredSummaryStats(newSummaryOptions("min-time", nil))
	stats.Record("read", 10, 0)
	stats.Record("read", 100, 0)
	stats.Record("write", 50, 0)

	entries := stats.sortedEntries()
	if len(entries) != 2 || entries[0].name != "write" {
		t.Fatalf("min-time order = %v, want write first", summaryEntryNames(entries))
	}

	stats.options.sortBy = summaryColumnMaxTime
	entries = stats.sortedEntries()
	if entries[0].name != "read" {
		t.Fatalf("max-time order = %v, want read first", summaryEntryNames(entries))
	}
}

func TestSummaryPipelineAppliesStatusFilterBeforeRecording(t *testing.T) {
	stats := newSummaryStats()
	policy := newTraceOutputPolicy(&cli.Options{SummaryOnly: true, FailedOnly: true})
	pipeline := newSyscallExitPipeline(SyscallExitPipelineDeps{
		Summary:     policy,
		EventPolicy: policy,
		Finalizer:   newTraceSessionSyscallExitFinalizer(stats, nil, nil),
	})

	pipeline.Handle(exitPipelineEventWithView("chdir", syscallEventView{valid: true, ret: 0}))
	pipeline.Handle(exitPipelineEventWithView("chdir", syscallEventView{valid: true, ret: -2}))

	if calls, _, _ := stats.totals(); calls != 1 {
		t.Fatalf("summary calls = %d, want only the failed syscall", calls)
	}
}

func summaryEntryNames(entries []summaryStatEntry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.name)
	}
	return names
}

func TestSummaryOptionsAppendNameColumn(t *testing.T) {
	options := newSummaryOptions("calls", []string{"calls"})
	if got := options.columns[len(options.columns)-1]; got != summaryColumnName {
		t.Fatalf("last summary column = %v, want name", got)
	}
	if strings.TrimSpace(summaryColumnHeader(summaryColumnName)) != "syscall" {
		t.Fatal("name column header must remain syscall")
	}
}
