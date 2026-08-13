package main

type traceScopePolicy interface {
	FollowForks() bool
	AttachPIDs() []int
}

type TraceScope struct {
	targetPID  int
	attachPIDs []int
	followFork bool
}

func newTraceScope(targetPID int, policy traceScopePolicy) TraceScope {
	scope := TraceScope{targetPID: targetPID}
	if policy != nil {
		scope.attachPIDs = append([]int(nil), policy.AttachPIDs()...)
		scope.followFork = policy.FollowForks()
	}
	return scope
}

func (scope TraceScope) AllowsPID(pid uint32) bool {
	if pid == 0 {
		return false
	}
	if scope.directlyMatches(int(pid)) {
		return true
	}
	return scope.followFork
}

func (scope TraceScope) AllowsEvent(pid uint32, tid uint32) bool {
	if pid == 0 && tid == 0 {
		return false
	}
	if (pid != 0 && scope.directlyMatches(int(pid))) ||
		(tid != 0 && scope.directlyMatches(int(tid))) {
		return true
	}
	return scope.followFork
}

func (scope TraceScope) directlyMatches(pid int) bool {
	if len(scope.attachPIDs) > 0 {
		for _, attachedPID := range scope.attachPIDs {
			if pid == attachedPID {
				return true
			}
		}
		return false
	}
	return pid == scope.targetPID
}
