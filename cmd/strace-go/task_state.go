package main

type TaskState struct {
	TID        uint32
	TGID       uint32
	ParentTID  uint32
	Alive      bool
	Execed     bool
	LastAction string
	LastSeenNS uint64
}

type pendingForkState struct {
	parentTGID uint32
}

func (st *TraceState) seedAttachTargets(pids []int) {
	if st == nil || len(pids) == 0 {
		return
	}
	if st.attachTargets == nil {
		st.attachTargets = make(map[uint32]struct{}, len(pids))
	}
	for _, pid := range pids {
		if pid > 0 {
			st.attachTargets[uint32(pid)] = struct{}{}
		}
	}
}

func (st *TraceState) AttachTargetsDone() bool {
	return st == nil || len(st.attachTargets) == 0
}

func (st *TraceState) markAttachTargetExited(pid uint32, tid uint32) {
	if st == nil || st.attachTargets == nil {
		return
	}
	if tid != 0 {
		delete(st.attachTargets, tid)
	}
	if pid != 0 && pid == tid {
		delete(st.attachTargets, pid)
	}
}

func (st *TraceState) markAttachTargetTerminated(view syscallEventView) {
	st.markAttachTargetExited(view.pid, view.tid)
	if st == nil || st.attachTargets == nil || view.pid == 0 {
		return
	}
	if syscallMeta(view.sysID).Name == "exit_group" {
		delete(st.attachTargets, view.pid)
	}
}

func snapshotTaskState(task *TaskState) *TaskState {
	if task == nil {
		return nil
	}
	snapshot := *task
	return &snapshot
}

func (st *TraceState) ensureTaskState(tid uint32, tgid uint32) *TaskState {
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

func (st *TraceState) noteSyscallTask(view syscallEventView) {
	if view.tid == 0 {
		return
	}
	task := st.ensureTaskState(view.tid, view.pid)
	task.Alive = true
	task.LastSeenNS = view.enterTime
}

func (st *TraceState) applyLifecycleEvent(view lifecycleEventView) (*TaskState, *processStateInheritance) {
	switch view.action {
	case lifecycleFork:
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
		child.Alive = true
		child.LastAction = "fork"
		child.LastSeenNS = view.enterTime
		if st.trackForkIdentity {
			if st.pendingForks == nil {
				st.pendingForks = make(map[uint32]pendingForkState)
			}
			st.pendingForks[childTID] = pendingForkState{
				parentTGID: parentTGID,
			}
		}
		return child, st.resolveForkIdentity(childTID, child.TGID)
	case lifecycleExec:
		tid := uint32(view.args[1])
		if tid == 0 {
			tid = view.tid
		}
		processInherit := st.resolveForkIdentity(tid, view.pid)
		task := st.ensureTaskState(tid, view.pid)
		task.Execed = true
		task.Alive = true
		task.LastAction = "exec"
		task.LastSeenNS = view.enterTime
		return task, processInherit
	case lifecycleExit:
		processInherit := st.resolveForkIdentity(view.tid, view.pid)
		task := st.ensureTaskState(view.tid, view.pid)
		task.Alive = false
		task.LastAction = "exit"
		task.LastSeenNS = view.enterTime
		return task, processInherit
	case lifecycleFree:
		processInherit := st.resolveForkIdentity(view.tid, view.pid)
		task := st.ensureTaskState(view.tid, view.pid)
		task.Alive = false
		task.LastAction = "free"
		task.LastSeenNS = view.enterTime
		return task, processInherit
	default:
		processInherit := st.resolveForkIdentity(view.tid, view.pid)
		task := st.ensureTaskState(view.tid, view.pid)
		task.LastAction = "unknown"
		task.LastSeenNS = view.enterTime
		return task, processInherit
	}
}

func (st *TraceState) resolveForkIdentity(tid uint32, tgid uint32) *processStateInheritance {
	if tid == 0 || st.pendingForks == nil {
		return nil
	}
	relation, ok := st.pendingForks[tid]
	if !ok {
		return nil
	}
	if tgid == 0 {
		return nil
	}
	delete(st.pendingForks, tid)
	if tgid != tid {
		return nil
	}
	return &processStateInheritance{parentTGID: relation.parentTGID, childTGID: tgid}
}
