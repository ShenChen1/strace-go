package main

import "strace-go/pkg/handler"

const syscallDecodePlanTableSize = 512

// syscallDecodePlan is the immutable event-side projection of the handler
// capability. Known syscall IDs never need an interface call in the hot path.
type syscallDecodePlan struct {
	needsDecode [syscallDecodePlanTableSize]bool
	present     [syscallDecodePlanTableSize]bool
	fallback    handler.HandlerDecodePlanPort
}

func newSyscallDecodePlan(
	metadata *syscallMetadataTable,
	fallback handler.HandlerDecodePlanPort,
) *syscallDecodePlan {
	plan := &syscallDecodePlan{fallback: fallback}
	if metadata == nil {
		return plan
	}
	for id := uint32(0); id < uint32(len(plan.present)); id++ {
		syscall, ok := metadata.lookup(id)
		if !ok {
			continue
		}
		plan.present[id] = true
		plan.needsDecode[id] = fallback == nil || fallback.NeedsDecode(id, syscall.Name)
	}
	return plan
}

func (plan *syscallDecodePlan) needs(id uint32, name string) bool {
	if plan == nil {
		return true
	}
	if id < uint32(len(plan.present)) && plan.present[id] {
		return plan.needsDecode[id]
	}
	if plan.fallback == nil {
		return true
	}
	return plan.fallback.NeedsDecode(id, name)
}
