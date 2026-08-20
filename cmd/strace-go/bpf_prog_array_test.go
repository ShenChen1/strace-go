package main

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

type recordedProgArrayWrite struct {
	index uint32
	prog  *ebpf.Program
}

type fakeProgArrayWriter struct {
	writes  []recordedProgArrayWrite
	failAt  int
	failErr error
}

func (w *fakeProgArrayWriter) Put(key, value interface{}) error {
	index, ok := key.(uint32)
	if !ok {
		return errors.New("unexpected prog array key type")
	}
	prog, ok := value.(*ebpf.Program)
	if !ok {
		return errors.New("unexpected prog array value type")
	}
	w.writes = append(w.writes, recordedProgArrayWrite{index: index, prog: prog})
	if len(w.writes)-1 == w.failAt {
		return w.failErr
	}
	return nil
}

func TestPutProgArrayEntriesWritesInOrder(t *testing.T) {
	first := &ebpf.Program{}
	second := &ebpf.Program{}
	writer := &fakeProgArrayWriter{failAt: -1}
	entries := []progArrayEntry{{index: 2, prog: first}, {index: 5, prog: second}}

	if err := putProgArrayEntries("exit_progs", writer, entries); err != nil {
		t.Fatalf("putProgArrayEntries() error = %v", err)
	}
	if len(writer.writes) != len(entries) {
		t.Fatalf("writes = %d, want %d", len(writer.writes), len(entries))
	}
	for index, want := range entries {
		got := writer.writes[index]
		if got.index != want.index || got.prog != want.prog {
			t.Fatalf("write[%d] = (%d, %p), want (%d, %p)", index, got.index, got.prog, want.index, want.prog)
		}
	}
}

func TestPutProgArrayEntriesRejectsNilHandler(t *testing.T) {
	writer := &fakeProgArrayWriter{failAt: -1}
	err := putProgArrayEntries("exit_progs", writer, []progArrayEntry{{index: 7}})
	if err == nil || !strings.Contains(err.Error(), "exit_progs[7]: nil handler") {
		t.Fatalf("putProgArrayEntries() error = %v, want nil handler error", err)
	}
	if len(writer.writes) != 0 {
		t.Fatalf("writes = %d, want 0 after nil handler", len(writer.writes))
	}
}

func TestPutProgArrayEntriesStopsAfterWriterFailure(t *testing.T) {
	writer := &fakeProgArrayWriter{failAt: 1, failErr: errors.New("map update failed")}
	entries := []progArrayEntry{
		{index: 1, prog: &ebpf.Program{}},
		{index: 4, prog: &ebpf.Program{}},
		{index: 8, prog: &ebpf.Program{}},
	}

	err := putProgArrayEntries("exit_progs", writer, entries)
	if err == nil || !strings.Contains(err.Error(), "exit_progs[4]: map update failed") {
		t.Fatalf("putProgArrayEntries() error = %v, want indexed writer error", err)
	}
	if len(writer.writes) != 2 {
		t.Fatalf("writes = %d, want 2 after writer failure", len(writer.writes))
	}
}

func TestPopulateProgArraysPreservesMapOrder(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/bpf_attach.go"))
	last := -1
	for _, name := range []string{
		"bpfMapEnterProgs",
		"bpfMapMmsgBytesProgs",
		"bpfMapExitProgs",
		"bpfMapRecvmsgProgs",
	} {
		index := strings.Index(source, "putProgArrayEntries("+name+",")
		if index < 0 {
			t.Fatalf("populateProgArrays missing %s writer call", name)
		}
		if index <= last {
			t.Fatalf("populateProgArrays map order moved at %s", name)
		}
		last = index
	}
}
