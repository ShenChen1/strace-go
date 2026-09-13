package main

func (st *TraceState) TaintHistory() {
	if st == nil {
		return
	}
	st.tainted = true
	for tid := range st.correlation.pendingSyscalls {
		st.correlation.clearTask(tid)
	}
	for tid := range st.correlation.pendingExits {
		st.correlation.clearTask(tid)
	}
	clear(st.correlation.pendingExecArgs)
	clear(st.correlation.suspendedSyscalls)
	st.unfinished.setEnabled(false, &st.correlation)
	clear(st.lifecycle.pendingForks)
	st.lifecycle.historyTainted = true
	for _, task := range st.lifecycle.tasks {
		task.ParentTID = 0
		task.Executable = ""
		task.Execed = false
		task.ExecReplaced = false
	}
}

func (st *FDStateStore) TaintHistory() {
	if st == nil || st.tainted {
		return
	}
	st.tainted = true
	clear(st.paths)
	clear(st.offsets)
	clear(st.fdStates)
	clear(st.fdCloexec)
}
