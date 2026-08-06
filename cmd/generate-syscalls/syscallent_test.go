package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSyscallentParsesEntriesAndRelativeIncludes(t *testing.T) {
	dir := t.TempDir()
	mainPath := filepath.Join(dir, "syscallent.h")
	writeFile(t, mainPath, strings.Join([]string{
		`[ 0] = { 3, TD, SEN(read), "read" },`,
		`#include "extra.h"`,
		`[ 2] = { 1, TF|TP, SEN(open), "open" },`,
	}, "\n"))
	writeFile(t, filepath.Join(dir, "extra.h"), `[ 1] = { 3, TD, SEN(write), "write" },`)

	got, err := parseSyscallent(mainPath)
	if err != nil {
		t.Fatalf("parseSyscallent() error = %v", err)
	}
	want := []syscallentEntry{
		{ID: 0, Name: "read", Argc: 3, Flags: "TD"},
		{ID: 1, Name: "write", Argc: 3, Flags: "TD"},
		{ID: 2, Name: "open", Argc: 1, Flags: "TF|TP"},
	}
	if !sameSyscallentEntries(got, want) {
		t.Fatalf("parseSyscallent() = %#v, want %#v", got, want)
	}
}

func TestParseSyscallentUsesGenericIncludeFallback(t *testing.T) {
	root := t.TempDir()
	archDir := filepath.Join(root, "x86_64")
	genericDir := filepath.Join(root, "generic")
	mainPath := filepath.Join(archDir, "syscallent.h")
	writeFile(t, mainPath, `#include "syscallent-common.h"`)
	writeFile(t, filepath.Join(genericDir, "syscallent-common.h"), `[BASE_NR + 424] = { 4, TD|TS|TP, SEN(pidfd_send_signal), "pidfd_send_signal" },`)

	got, err := parseSyscallent(mainPath)
	if err != nil {
		t.Fatalf("parseSyscallent() error = %v", err)
	}
	want := []syscallentEntry{
		{ID: 424, Name: "pidfd_send_signal", Argc: 4, Flags: "TD|TS|TP"},
	}
	if !sameSyscallentEntries(got, want) {
		t.Fatalf("parseSyscallent() = %#v, want %#v", got, want)
	}
}

func TestParseSyscallentReportsMissingInclude(t *testing.T) {
	path := filepath.Join(t.TempDir(), "syscallent.h")
	writeFile(t, path, `#include "missing.h"`)

	_, err := syscallentParser{}.ParseFile(path)
	if err == nil || !strings.Contains(err.Error(), "resolve include") {
		t.Fatalf("ParseFile() error = %v, want include context", err)
	}
}

func sameSyscallentEntries(a []syscallentEntry, b []syscallentEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
