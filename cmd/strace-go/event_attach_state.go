package main

import (
	"errors"
	"fmt"
)

var errTraceAttachExitReaderUnavailable = errors.New("attach exit reader unavailable")

// traceAttachState owns attached roots and event-time exit fact refresh.
type traceAttachState struct {
	targets       map[uint32]struct{}
	exitReader    traceAttachExitReader
	readerEnabled bool
}

func (st *traceAttachState) seedTargets(pids []int) {
	if st == nil || len(pids) == 0 {
		return
	}
	if st.targets == nil {
		st.targets = make(map[uint32]struct{}, len(pids))
	}
	for _, pid := range pids {
		if pid > 0 {
			st.targets[uint32(pid)] = struct{}{}
		}
	}
}

func (st *traceAttachState) targetsDone() bool {
	return st == nil || len(st.targets) == 0
}

func (st *traceAttachState) setExitReader(reader traceAttachExitReader) {
	if st == nil {
		return
	}
	st.exitReader = reader
	st.readerEnabled = true
}

func (st *traceAttachState) targetExitFact(pid uint32) (bool, error) {
	if st == nil || pid == 0 {
		return false, nil
	}
	if st.exitReader == nil {
		if st.readerEnabled {
			return false, errTraceAttachExitReaderUnavailable
		}
		return false, nil
	}
	exited, err := st.exitReader.IsExited(pid)
	if err != nil {
		return false, fmt.Errorf("refresh command target %d: %w", pid, err)
	}
	return exited, nil
}

func (st *traceAttachState) refreshTargets() error {
	if st == nil || len(st.targets) == 0 {
		return nil
	}
	if st.exitReader == nil {
		if st.readerEnabled {
			return errTraceAttachExitReaderUnavailable
		}
		return nil
	}
	for pid := range st.targets {
		exited, err := st.exitReader.IsExited(pid)
		if err != nil {
			return fmt.Errorf("refresh attach target %d: %w", pid, err)
		}
		if exited {
			delete(st.targets, pid)
		}
	}
	return nil
}

func (st *traceAttachState) markTargetExited(pid uint32, tid uint32) {
	if st == nil || st.targets == nil {
		return
	}
	if tid != 0 {
		delete(st.targets, tid)
	}
	if pid != 0 && pid == tid {
		delete(st.targets, pid)
	}
}

func (st *traceAttachState) markTargetTerminated(view *syscallEventView) {
	if st == nil || view == nil {
		return
	}
	st.markTargetExited(view.pid, view.tid)
	if st.targets == nil || view.pid == 0 {
		return
	}
	if syscallMeta(view.sysID).Name == "exit_group" {
		delete(st.targets, view.pid)
	}
}

func (st *TraceState) seedAttachTargets(pids []int) {
	if st == nil {
		return
	}
	st.attach.seedTargets(pids)
}

func (st *TraceState) AttachTargetsDone() bool {
	if st == nil {
		return true
	}
	return st.attach.targetsDone()
}

func (st *TraceState) setAttachExitReader(reader traceAttachExitReader) {
	if st == nil {
		return
	}
	st.attach.setExitReader(reader)
}

func (st *TraceState) TargetLifecycleExited(pid uint32) (bool, error) {
	if st == nil || pid == 0 {
		return false, nil
	}
	if st.lifecycle.lifecycleEventObserved(pid) {
		return true, nil
	}
	return st.attach.targetExitFact(pid)
}

func (st *TraceState) RefreshAttachTargets() error {
	if st == nil {
		return nil
	}
	return st.attach.refreshTargets()
}

func (st *TraceState) markAttachTargetExited(pid uint32, tid uint32) {
	if st == nil {
		return
	}
	st.attach.markTargetExited(pid, tid)
}

func (st *TraceState) markAttachTargetTerminated(view *syscallEventView) {
	if st == nil {
		return
	}
	st.attach.markTargetTerminated(view)
}
