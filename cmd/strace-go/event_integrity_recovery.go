package main

// Epochs invalidate task trust lazily; candidates never survive a loss barrier.
type traceTaskIntegrity struct {
	pid       uint32
	epoch     uint64
	clean     bool
	candidate bool
	sysID     uint32
	enterTime uint64
	args      [6]uint64
}

func (i *TraceIntegrity) correlationTainted(tid uint32) bool {
	if !i.snapshot.Tainted {
		return false
	}
	task, ok := i.tasks[tid]
	return !ok || task.epoch != i.snapshot.Epoch || !task.clean
}

func (i *TraceIntegrity) observeTask(ev *traceEventEnvelope) {
	if ev.tid == 0 {
		return
	}
	if ev.isLifecycle() {
		i.observeTaskLifecycle(ev)
		return
	}
	task := i.tasks[ev.tid]
	if task.epoch != i.snapshot.Epoch {
		task = traceTaskIntegrity{epoch: i.snapshot.Epoch}
	}
	task.pid = ev.pid
	if !i.snapshot.Tainted {
		task.clean = true
	}
	view := ev.syscallView()
	if view.isGenericEnter() {
		task.candidate = true
		task.sysID, task.enterTime, task.args = ev.sysID, ev.enterTime, ev.args
	} else if view.isExit() && !view.isExitFragment() {
		matched := task.candidate && task.sysID == ev.sysID && task.enterTime == ev.enterTime && task.args == ev.args
		if matched && !task.clean {
			i.snapshot.RecoveredDomains++
			task.clean = true
		}
		task.candidate = false
	}
	i.tasks[ev.tid] = task
}

func (i *TraceIntegrity) observeTaskLifecycle(ev *traceEventEnvelope) {
	switch ev.lifecycleAction {
	case lifecycleExit, lifecycleFree:
		delete(i.tasks, ev.tid)
	case lifecycleExec:
		delete(i.tasks, uint32(ev.args[0]))
		tid := uint32(ev.args[1])
		if tid == 0 {
			tid = ev.tid
		}
		i.tasks[tid] = traceTaskIntegrity{pid: ev.pid, epoch: i.snapshot.Epoch, clean: !i.snapshot.Tainted}
	case lifecycleFork:
		child := uint32(ev.args[1])
		if child != 0 {
			i.tasks[child] = traceTaskIntegrity{epoch: i.snapshot.Epoch, clean: !i.snapshot.Tainted}
		}
	}
}
