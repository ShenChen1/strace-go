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

func (s *traceSession) ensureTaskState(tid uint32, tgid uint32) *TaskState {
	if s.tasks == nil {
		s.tasks = make(map[uint32]*TaskState)
	}
	task := s.tasks[tid]
	if task == nil {
		task = &TaskState{TID: tid}
		s.tasks[tid] = task
	}
	if tgid != 0 {
		task.TGID = tgid
	} else if task.TGID == 0 {
		task.TGID = tid
	}
	return task
}

func (s *traceSession) noteSyscallTask(eventRaw *bpfEvent) {
	if eventRaw.Tid == 0 {
		return
	}
	task := s.ensureTaskState(eventRaw.Tid, eventRaw.Pid)
	task.Alive = true
	task.LastSeenNS = eventRaw.EnterTime
}

func (s *traceSession) applyLifecycleEvent(eventRaw *bpfEvent) *TaskState {
	switch eventRaw.EventFlags {
	case lifecycleFork:
		parentTID := uint32(eventRaw.Args[0])
		childTID := uint32(eventRaw.Args[1])
		parent := s.ensureTaskState(parentTID, eventRaw.Pid)
		parent.Alive = true
		parent.LastAction = "fork"
		parent.LastSeenNS = eventRaw.EnterTime

		child := s.ensureTaskState(childTID, childTID)
		child.ParentTID = parentTID
		child.Alive = true
		child.LastAction = "fork"
		child.LastSeenNS = eventRaw.EnterTime
		return child
	case lifecycleExec:
		tid := uint32(eventRaw.Args[1])
		if tid == 0 {
			tid = eventRaw.Tid
		}
		task := s.ensureTaskState(tid, eventRaw.Pid)
		task.Execed = true
		task.Alive = true
		task.LastAction = "exec"
		task.LastSeenNS = eventRaw.EnterTime
		return task
	case lifecycleExit:
		task := s.ensureTaskState(eventRaw.Tid, eventRaw.Pid)
		task.Alive = false
		task.LastAction = "exit"
		task.LastSeenNS = eventRaw.EnterTime
		return task
	case lifecycleFree:
		task := s.ensureTaskState(eventRaw.Tid, eventRaw.Pid)
		task.Alive = false
		task.LastAction = "free"
		task.LastSeenNS = eventRaw.EnterTime
		return task
	default:
		task := s.ensureTaskState(eventRaw.Tid, eventRaw.Pid)
		task.LastAction = "unknown"
		task.LastSeenNS = eventRaw.EnterTime
		return task
	}
}
