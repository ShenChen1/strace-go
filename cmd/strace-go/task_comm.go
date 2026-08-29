package main

import (
	"strings"

	"strace-go/pkg/format"
)

type taskCommStore struct {
	byPID map[uint32]string
}

type traceTaskCommObserver interface {
	ObserveTaskComm(pid uint32, comm string)
}

func newTaskCommStore() *taskCommStore {
	return &taskCommStore{}
}

func (s *taskCommStore) Observe(pid uint32, comm string) {
	if s == nil || pid == 0 {
		return
	}
	if end := strings.IndexByte(comm, 0); end >= 0 {
		comm = comm[:end]
	}
	if s.byPID == nil {
		s.byPID = make(map[uint32]string)
	}
	s.byPID[pid] = comm
}

func (s *taskCommStore) Lookup(pid uint32) (string, bool) {
	if s == nil || s.byPID == nil {
		return "", false
	}
	comm, ok := s.byPID[pid]
	return comm, ok
}

func (s *taskCommStore) Forget(pid uint32) {
	if s != nil {
		delete(s.byPID, pid)
	}
}

func escapeTaskComm(comm string) string {
	escaped := format.BufferEscape([]byte(comm), len(comm), len(comm), 0)
	if len(escaped) >= 2 {
		escaped = escaped[1 : len(escaped)-1]
	}
	escaped = strings.ReplaceAll(escaped, "<", `\x3c`)
	return strings.ReplaceAll(escaped, ">", `\x3e`)
}

func (r *TextRenderer) ObserveTaskComm(pid uint32, comm string) {
	if r != nil && r.taskComms != nil && comm != "" {
		r.taskComms.Observe(pid, comm)
	}
}

var _ traceTaskCommObserver = (*TextRenderer)(nil)
