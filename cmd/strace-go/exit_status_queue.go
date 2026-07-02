package main

import (
	"fmt"
	"io"
)

type ExitStatusQueue struct {
	pending map[int]string
	exited  map[int]bool
}

type ExitStatusCoordinator struct {
	queue      *ExitStatusQueue
	out        io.Writer
	hasCommand bool
	attachPids []int
}

type ExitStatusCoordinatorDeps struct {
	Queue      *ExitStatusQueue
	Out        io.Writer
	HasCommand bool
	AttachPids []int
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

func newExitStatusCoordinator(deps ExitStatusCoordinatorDeps) *ExitStatusCoordinator {
	return &ExitStatusCoordinator{
		queue:      deps.Queue,
		out:        deps.Out,
		hasCommand: deps.HasCommand,
		attachPids: append([]int(nil), deps.AttachPids...),
	}
}

func (s *traceSession) exitStatusCoordinator() *ExitStatusCoordinator {
	attachPids := []int(nil)
	if s.opts != nil {
		attachPids = s.opts.AttachPids
	}
	return newExitStatusCoordinator(ExitStatusCoordinatorDeps{
		Queue:      s.exitStatusQueue(),
		Out:        s.outWriter,
		HasCommand: s.cmd != nil,
		AttachPids: attachPids,
	})
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

func (c *ExitStatusCoordinator) ShouldQueue(tgid int) bool {
	if c == nil || !c.hasCommand {
		return false
	}
	for _, pid := range c.attachPids {
		if pid == tgid {
			return false
		}
	}
	return true
}

func (c *ExitStatusCoordinator) Queue(pid int, line string) {
	if c == nil || c.queue == nil {
		return
	}
	if line, ok := c.queue.Queue(pid, line); ok {
		c.write(line)
	}
}

func (c *ExitStatusCoordinator) MarkExited(pid int) {
	if c == nil || c.queue == nil {
		return
	}
	if line, ok := c.queue.MarkExited(pid); ok {
		c.write(line)
	}
}

func (c *ExitStatusCoordinator) Discard(pid int) {
	if c == nil || c.queue == nil {
		return
	}
	c.queue.Discard(pid)
}

func (c *ExitStatusCoordinator) write(line string) {
	if c.out != nil {
		fmt.Fprint(c.out, line)
	}
}
