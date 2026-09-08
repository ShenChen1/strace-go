package main

type TaskState struct {
	TID          uint32
	TGID         uint32
	ParentTID    uint32
	Alive        bool
	Execed       bool
	ExecReplaced bool
	Executable   string
	LastAction   string
	LastSeenNS   uint64
}

type pendingForkState struct {
	parentTGID uint32
}

// traceTaskLifecycleState owns task identity and lifecycle completion facts.
// Cross-owner pending cleanup remains coordinated by TraceState.
type traceTaskLifecycleState struct {
	trackForkIdentity bool
	tasks             map[uint32]*TaskState
	pendingForks      map[uint32]pendingForkState
	lifecyclePending  map[uint32]struct{}
	commandTargetPID  uint32
	lifecycleExited   map[uint32]struct{}
}

func snapshotTaskState(task *TaskState) *TaskState {
	if task == nil {
		return nil
	}
	snapshot := *task
	return &snapshot
}

func (st *traceTaskLifecycleState) markLifecyclePending(tid uint32) {
	if st == nil || tid == 0 {
		return
	}
	if st.lifecyclePending == nil {
		st.lifecyclePending = make(map[uint32]struct{})
	}
	st.lifecyclePending[tid] = struct{}{}
}

func (st *traceTaskLifecycleState) clearLifecyclePending(tid uint32) {
	if st == nil || st.lifecyclePending == nil {
		return
	}
	delete(st.lifecyclePending, tid)
}

func (st *traceTaskLifecycleState) setCommandTargetPID(pid int) {
	if st == nil || pid <= 0 {
		return
	}
	st.commandTargetPID = uint32(pid)
}

func (st *traceTaskLifecycleState) rememberLifecycleExit(pid uint32, tid uint32) {
	if st == nil || st.commandTargetPID == 0 ||
		(st.commandTargetPID != pid && st.commandTargetPID != tid) {
		return
	}
	if st.lifecycleExited == nil {
		st.lifecycleExited = make(map[uint32]struct{}, 2)
	}
	if pid != 0 {
		st.lifecycleExited[pid] = struct{}{}
	}
	if tid != 0 {
		st.lifecycleExited[tid] = struct{}{}
	}
}

func (st *traceTaskLifecycleState) lifecycleEventObserved(pid uint32) bool {
	if st == nil || pid == 0 {
		return false
	}
	_, ok := st.lifecycleExited[pid]
	return ok
}

func (st *traceTaskLifecycleState) quiescent(pid uint32) bool {
	if st == nil || pid == 0 {
		return false
	}
	for _, task := range st.tasks {
		if task != nil && task.Alive {
			return false
		}
	}
	if len(st.lifecyclePending) != 0 {
		return false
	}
	for _, fork := range st.pendingForks {
		if fork.parentTGID == pid {
			return false
		}
	}
	return true
}

func (st *traceTaskLifecycleState) ensureTaskState(tid uint32, tgid uint32) *TaskState {
	if st.tasks == nil {
		st.tasks = make(map[uint32]*TaskState)
	}
	task := st.tasks[tid]
	if task == nil {
		task = &TaskState{TID: tid}
		st.tasks[tid] = task
	}
	if tgid != 0 {
		task.TGID = tgid
	}
	return task
}

func (st *traceTaskLifecycleState) noteSyscallTask(view *syscallEventView) {
	if view.tid == 0 {
		return
	}
	task := st.ensureTaskState(taskTIDForSyscall(view), view.pid)
	task.Alive = true
	task.LastSeenNS = view.enterTime
}

func taskTIDForSyscall(view *syscallEventView) uint32 {
	if !isExitView(view) || view.ret != 0 || view.pid == 0 || view.pid == view.tid {
		return view.tid
	}
	name := syscallMeta(view.sysID).Name
	if name == "execve" || name == "execveat" {
		return view.pid
	}
	return view.tid
}

func (st *traceTaskLifecycleState) applyLifecycleEvent(view lifecycleEventView) (*TaskState, *processStateInheritance) {
	switch view.action {
	case lifecycleUnknownDetach, lifecycleUnknownExit:
		return nil, nil
	case lifecycleFork:
		return st.applyFork(view)
	case lifecycleExec:
		return st.applyExec(view)
	case lifecycleExit, lifecycleFree:
		return st.applyTaskExit(view)
	default:
		processInherit := st.resolveForkIdentity(view.tid, view.pid)
		task := st.ensureTaskState(view.tid, view.pid)
		task.LastAction = "unknown"
		task.LastSeenNS = view.enterTime
		return task, processInherit
	}
}

func (st *traceTaskLifecycleState) applyFork(view lifecycleEventView) (*TaskState, *processStateInheritance) {
	parentTID := view.tid
	if parentTID == 0 {
		parentTID = uint32(view.args[0])
	}
	parentTGID := view.pid
	if parentTGID == 0 {
		parentTGID = uint32(view.args[0])
	}
	childTID := uint32(view.args[1])
	parent := st.ensureTaskState(parentTID, parentTGID)
	parent.Alive = true
	parent.LastAction = "fork"
	parent.LastSeenNS = view.enterTime

	child := &TaskState{TID: childTID}
	if st.trackForkIdentity {
		child = st.ensureTaskState(childTID, 0)
	}
	child.ParentTID = parentTID
	child.Executable = parent.Executable
	child.Alive = true
	child.LastAction = "fork"
	child.LastSeenNS = view.enterTime
	if st.trackForkIdentity {
		if st.pendingForks == nil {
			st.pendingForks = make(map[uint32]pendingForkState)
		}
		st.pendingForks[childTID] = pendingForkState{parentTGID: parentTGID}
	}
	return child, st.resolveForkIdentity(childTID, child.TGID)
}

func (st *traceTaskLifecycleState) applyExec(view lifecycleEventView) (*TaskState, *processStateInheritance) {
	tid := uint32(view.args[1])
	if tid == 0 {
		tid = view.tid
	}
	oldTID := uint32(view.args[0])
	identityTID := tid
	if oldTID != 0 {
		identityTID = oldTID
	}
	processInherit := st.resolveForkIdentity(identityTID, view.pid)
	task := st.ensureExecTaskState(oldTID, tid, view.pid)
	task.Execed = true
	task.ExecReplaced = oldTID != 0 && oldTID != tid
	task.Executable = view.snapshotText
	task.Alive = true
	task.LastAction = "exec"
	task.LastSeenNS = view.enterTime
	return task, processInherit
}

func (st *traceTaskLifecycleState) applyTaskExit(view lifecycleEventView) (*TaskState, *processStateInheritance) {
	processInherit := st.resolveForkIdentity(view.tid, view.pid)
	task := st.ensureTaskState(view.tid, view.pid)
	task.Alive = false
	if view.action == lifecycleExit {
		task.LastAction = "exit"
	} else {
		task.LastAction = "free"
	}
	task.LastSeenNS = view.enterTime
	return task, processInherit
}

func (st *traceTaskLifecycleState) ensureExecTaskState(oldTID uint32, tid uint32, tgid uint32) *TaskState {
	if oldTID == 0 || oldTID == tid {
		return st.ensureTaskState(tid, tgid)
	}

	task := st.tasks[tid]
	oldTask := st.tasks[oldTID]
	delete(st.tasks, oldTID)
	if task != nil {
		if tgid != 0 {
			task.TGID = tgid
		}
		return task
	}
	if oldTask == nil {
		return st.ensureTaskState(tid, tgid)
	}

	oldTask.TID = tid
	if tgid != 0 {
		oldTask.TGID = tgid
	}
	st.tasks[tid] = oldTask
	return oldTask
}

func (st *traceTaskLifecycleState) resolveForkIdentity(tid uint32, tgid uint32) *processStateInheritance {
	if tid == 0 || st.pendingForks == nil {
		return nil
	}
	relation, ok := st.pendingForks[tid]
	if !ok || tgid == 0 {
		return nil
	}
	delete(st.pendingForks, tid)
	if tgid != tid {
		return nil
	}
	return &processStateInheritance{parentTGID: relation.parentTGID, childTGID: tgid}
}

func (st *traceTaskLifecycleState) clearTask(tid uint32) {
	if st == nil {
		return
	}
	delete(st.pendingForks, tid)
}

func (st *traceTaskLifecycleState) retireTask(tid uint32) {
	if st == nil || tid == 0 {
		return
	}
	delete(st.tasks, tid)
}

func (st *TraceState) setCommandTargetPID(pid int) {
	if st == nil {
		return
	}
	st.lifecycle.setCommandTargetPID(pid)
}

func (st *TraceState) rememberLifecycleExit(pid uint32, tid uint32) {
	if st == nil {
		return
	}
	st.lifecycle.rememberLifecycleExit(pid, tid)
}

func (st *TraceState) TargetLifecycleEventObserved(pid uint32) bool {
	if st == nil {
		return false
	}
	return st.lifecycle.lifecycleEventObserved(pid)
}

func (st *TraceState) TargetLifecycleQuiescent(pid uint32) bool {
	if st == nil {
		return false
	}
	return st.lifecycle.quiescent(pid)
}

func (st *TraceState) markLifecyclePending(tid uint32) {
	if st == nil {
		return
	}
	st.lifecycle.markLifecyclePending(tid)
}

func (st *TraceState) clearLifecyclePending(tid uint32) {
	if st == nil {
		return
	}
	st.lifecycle.clearLifecyclePending(tid)
}

func (st *TraceState) ensureTaskState(tid uint32, tgid uint32) *TaskState {
	if st == nil {
		return nil
	}
	return st.lifecycle.ensureTaskState(tid, tgid)
}

func (st *TraceState) noteSyscallTask(view *syscallEventView) {
	if st == nil {
		return
	}
	st.lifecycle.noteSyscallTask(view)
}

func (st *TraceState) applyLifecycleEvent(view lifecycleEventView) (*TaskState, *processStateInheritance) {
	if st == nil {
		return nil, nil
	}
	if view.action == lifecycleExec {
		tid := uint32(view.args[1])
		if tid == 0 {
			tid = view.tid
		}
		oldTID := uint32(view.args[0])
		if oldTID != 0 && oldTID != tid {
			st.clearTaskPending(tid)
		}
	}
	return st.lifecycle.applyLifecycleEvent(view)
}

func (st *TraceState) resolveForkIdentity(tid uint32, tgid uint32) *processStateInheritance {
	if st == nil {
		return nil
	}
	return st.lifecycle.resolveForkIdentity(tid, tgid)
}

func (st *TraceState) clearTaskPending(tid uint32) {
	if st == nil {
		return
	}
	st.unfinished.deleteCandidate(tid)
	st.correlation.clearTask(tid)
	st.lifecycle.clearTask(tid)
}

func (st *TraceState) retireTask(tid uint32) {
	if st == nil || tid == 0 {
		return
	}
	st.clearTaskPending(tid)
	st.lifecycle.retireTask(tid)
}
