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
	} else if task.TGID == 0 {
		task.TGID = tid
	}
	return task
}

func (st *TraceState) noteSyscallTask(view traceStateEventView) {
	if view.tid == 0 {
		return
	}
	task := st.ensureTaskState(view.tid, view.pid)
	task.Alive = true
	task.LastSeenNS = view.enterTime
}

func (st *TraceState) applyLifecycleEvent(view lifecycleEventView) *TaskState {
	switch view.action {
	case lifecycleFork:
		parentTID := uint32(view.args[0])
		childTID := uint32(view.args[1])
		parent := st.ensureTaskState(parentTID, view.pid)
		parent.Alive = true
		parent.LastAction = "fork"
		parent.LastSeenNS = view.enterTime

		child := st.ensureTaskState(childTID, childTID)
		child.ParentTID = parentTID
		child.Alive = true
		child.LastAction = "fork"
		child.LastSeenNS = view.enterTime
		return child
	case lifecycleExec:
		tid := uint32(view.args[1])
		if tid == 0 {
			tid = view.tid
		}
		task := st.ensureTaskState(tid, view.pid)
		task.Execed = true
		task.Alive = true
		task.LastAction = "exec"
		task.LastSeenNS = view.enterTime
		return task
	case lifecycleExit:
		task := st.ensureTaskState(view.tid, view.pid)
		task.Alive = false
		task.LastAction = "exit"
		task.LastSeenNS = view.enterTime
		return task
	case lifecycleFree:
		task := st.ensureTaskState(view.tid, view.pid)
		task.Alive = false
		task.LastAction = "free"
		task.LastSeenNS = view.enterTime
		return task
	default:
		task := st.ensureTaskState(view.tid, view.pid)
		task.LastAction = "unknown"
		task.LastSeenNS = view.enterTime
		return task
	}
}
