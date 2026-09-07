package main

import (
	"fmt"
	"io"
)

type ExitStatusQueue struct {
	pending  map[int]string
	exited   map[int]bool
	fallback map[int]string
	released map[int]bool
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

func newExitStatusCoordinator(deps ExitStatusCoordinatorDeps) *ExitStatusCoordinator {
	return &ExitStatusCoordinator{
		queue:      deps.Queue,
		out:        deps.Out,
		hasCommand: deps.HasCommand,
		attachPids: append([]int(nil), deps.AttachPids...),
	}
}

func (s *traceSession) exitStatusCoordinator() *ExitStatusCoordinator {
	if s == nil || s.components == nil {
		return nil
	}
	return s.components.exitStatus
}

// IMPACT: Queue records an exit line until process wait confirms that tracee termination is visible.
func (q *ExitStatusQueue) Queue(pid int, line string) (string, bool) {
	if q.released != nil && q.released[pid] {
		return "", false
	}
	if q.pending == nil {
		q.pending = make(map[int]string)
	}
	q.pending[pid] = line
	return "", false
}

// IMPACT: MarkExited records process wait completion without overtaking lagging ringbuf records.
func (q *ExitStatusQueue) MarkExited(pid int) (string, bool) {
	return q.MarkExitedWithFallback(pid, "")
}

// IMPACT: MarkExitedWithFallback defers both real and wait-derived lines until the ringbuf drain completes.
func (q *ExitStatusQueue) MarkExitedWithFallback(pid int, fallback string) (string, bool) {
	if q.exited == nil {
		q.exited = make(map[int]bool)
	}
	q.exited[pid] = true
	if fallback != "" {
		if q.fallback == nil {
			q.fallback = make(map[int]string)
		}
		q.fallback[pid] = fallback
	}
	return "", false
}

func (q *ExitStatusQueue) Discard(pid int) {
	delete(q.pending, pid)
	delete(q.exited, pid)
	delete(q.fallback, pid)
	delete(q.released, pid)
}

func (q *ExitStatusQueue) HasExited(pid int) bool {
	return q.exited != nil && q.exited[pid]
}

func (q *ExitStatusQueue) FlushFallback(pid int) (string, bool) {
	if q.exited == nil || !q.exited[pid] {
		return "", false
	}
	line, ok := q.pending[pid]
	if !ok && q.fallback != nil {
		line, ok = q.fallback[pid]
	}
	delete(q.pending, pid)
	delete(q.exited, pid)
	delete(q.fallback, pid)
	if !ok || line == "" {
		return "", false
	}
	return line, true
}

// IMPACT: FlushAfterWait releases a command status early only for attach runs.
// A later ringbuf status for the same command is stale after this point.
func (q *ExitStatusQueue) FlushAfterWait(pid int) (string, bool) {
	line, ok := q.FlushFallback(pid)
	if !ok {
		return "", false
	}
	if q.released == nil {
		q.released = make(map[int]bool)
	}
	q.released[pid] = true
	return line, true
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
		c.write(pid, line)
	}
}

func (c *ExitStatusCoordinator) MarkExited(pid int) {
	if c == nil || c.queue == nil {
		return
	}
	if line, ok := c.queue.MarkExited(pid); ok {
		c.write(pid, line)
	}
}

func (c *ExitStatusCoordinator) MarkExitedWithFallback(pid int, fallback string) {
	if c == nil || c.queue == nil {
		return
	}
	if line, ok := c.queue.MarkExitedWithFallback(pid, fallback); ok {
		c.write(pid, line)
		return
	}
	if len(c.attachPids) == 0 {
		return
	}
	if line, ok := c.queue.FlushAfterWait(pid); ok {
		c.write(pid, line)
	}
}

func (c *ExitStatusCoordinator) FlushFallback(pid int) {
	if c == nil || c.queue == nil {
		return
	}
	if line, ok := c.queue.FlushFallback(pid); ok {
		c.write(pid, line)
	}
}

func (c *ExitStatusCoordinator) Discard(pid int) {
	if c == nil || c.queue == nil {
		return
	}
	c.queue.Discard(pid)
}

func (c *ExitStatusCoordinator) write(pid int, line string) {
	if c.out != nil {
		selectTraceOutputPID(c.out, pid)
		fmt.Fprint(c.out, line)
	}
}
