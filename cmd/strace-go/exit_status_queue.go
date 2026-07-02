package main

type ExitStatusQueue struct {
	pending map[int]string
	exited  map[int]bool
}

func newExitStatusQueue() *ExitStatusQueue {
	return &ExitStatusQueue{}
}

func (s *traceSession) exitStatusQueue() *ExitStatusQueue {
	if s.exitStatus == nil {
		s.exitStatus = newExitStatusQueue()
	}
	return s.exitStatus
}

// IMPACT: Queue records an exit line until process wait confirms that tracee termination is visible.
func (q *ExitStatusQueue) Queue(pid int, line string) (string, bool) {
	if q.exited != nil && q.exited[pid] {
		delete(q.exited, pid)
		return line, true
	}
	if q.pending == nil {
		q.pending = make(map[int]string)
	}
	q.pending[pid] = line
	return "", false
}

// IMPACT: MarkExited records process wait completion or releases a previously queued exit line.
func (q *ExitStatusQueue) MarkExited(pid int) (string, bool) {
	if q.pending != nil {
		if line, ok := q.pending[pid]; ok {
			delete(q.pending, pid)
			return line, true
		}
	}
	if q.exited == nil {
		q.exited = make(map[int]bool)
	}
	q.exited[pid] = true
	return "", false
}

func (q *ExitStatusQueue) Discard(pid int) {
	delete(q.pending, pid)
	delete(q.exited, pid)
}

func (q *ExitStatusQueue) HasExited(pid int) bool {
	return q.exited != nil && q.exited[pid]
}
