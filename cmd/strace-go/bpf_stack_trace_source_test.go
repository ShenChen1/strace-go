package main

import (
	"strings"
	"testing"
)

func TestBPFExitEventCarriesPendingStackID(t *testing.T) {
	sources := loadBPFSources(t)
	if !strings.Contains(sources.straceSource, "#define EVENT_V2_EXIT_BODY_LEN 80") {
		t.Fatal("exit event v2 body must reserve space for stack metadata")
	}
	for _, snippet := range []string{
		"s32 stack_id;",
		"u32 reserved;",
	} {
		if !strings.Contains(sources.straceSource, snippet) {
			t.Fatalf("exit event body is missing stack metadata snippet %q", snippet)
		}
	}
	for _, snippet := range []string{
		"body->stack_id = p->stack_id;",
		"body->reserved = 0;",
	} {
		if !strings.Contains(sources.directHeader, snippet) {
			t.Fatalf("direct exit event is missing stack metadata snippet %q", snippet)
		}
	}
}

func TestBPFStackIDSurvivesEventHelpers(t *testing.T) {
	sources := loadBPFSources(t)
	if strings.Count(sources.straceSource, "volatile s32 stack_id = -1;") < 2 {
		t.Fatal("enter handlers must preserve stack id across event helper calls")
	}
}
