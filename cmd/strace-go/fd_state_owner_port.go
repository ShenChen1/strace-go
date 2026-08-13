package main

import (
	"strace-go/pkg/event"
	"strace-go/pkg/handler"
)

// traceFDStateOwner exists only at the session composition boundary.
// Runtime consumers receive one of its narrower reader or mutation ports.
type traceFDStateOwner interface {
	event.FDPathReader
	handler.FDStateReader
	fdStateUpdatePort
	fdOffsetUpdatePort
	fdCloseUpdatePort
	fdLifecycleUpdatePort
}

var _ traceFDStateOwner = (*FDStateStore)(nil)
