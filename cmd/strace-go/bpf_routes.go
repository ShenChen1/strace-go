package main

import (
	"fmt"
	"sort"

	"github.com/cilium/ebpf"

	"strace-go/pkg/meta"
)

type bpfRoutePlan struct {
	enter map[uint32]uint32
	exit  map[uint32]uint32
}

// bpfRouteCapability is the final capture policy for one syscall. A zero slot
// means that the generic handler owns that direction.
type bpfRouteCapability struct {
	enterSlot             uint32
	exitSlot              uint32
	standaloneExitElision bool
}

func isGenericEnterRoute(sysID uint32) bool {
	syscall, ok := meta.SyscallTable[sysID]
	if !ok {
		return true
	}
	capability, ok := bpfRouteCapabilities[syscall.Name]
	return !ok || capability.enterSlot == 0
}

func isPlainGenericEnterExitRoute(sysID uint32) bool {
	// Elision is safe only when both directions use the generic event; specialized exits may carry OUT payload.
	syscall, ok := meta.SyscallTable[sysID]
	if !ok {
		return true
	}
	capability, ok := bpfRouteCapabilities[syscall.Name]
	return !ok || (capability.enterSlot == 0 && capability.exitSlot == 0)
}

// Only these direct exits carry all args and their bounded OUT snapshot in one
// event, so text can synthesize their missing generic enter safely.
func isStandaloneExitElisionRoute(sysID uint32) bool {
	syscall, ok := meta.SyscallTable[sysID]
	if !ok || !isGenericEnterRoute(sysID) {
		return false
	}
	capability, ok := bpfRouteCapabilities[syscall.Name]
	if !ok || capability.exitSlot == 0 {
		return false
	}
	return capability.standaloneExitElision
}

func newBPFRoutePlan(table map[uint32]meta.Syscall) (bpfRoutePlan, error) {
	return newBPFRoutePlanWithCapabilities(table, bpfRouteCapabilities)
}

func newBPFRoutePlanWithCapabilities(
	table map[uint32]meta.Syscall,
	capabilities map[string]bpfRouteCapability,
) (bpfRoutePlan, error) {
	ids := make(map[string]uint32, len(table))
	plan := bpfRoutePlan{
		enter: make(map[uint32]uint32, len(table)),
		exit:  make(map[uint32]uint32, len(table)),
	}
	if err := validateBPFRouteCapabilities(capabilities); err != nil {
		return bpfRoutePlan{}, err
	}
	for id, syscall := range table {
		if id >= bpfRouteMapMaxEntries {
			return bpfRoutePlan{}, fmt.Errorf("syscall id %d exceeds BPF route map capacity %d", id, bpfRouteMapMaxEntries)
		}
		if previous, exists := ids[syscall.Name]; exists && previous != id {
			return bpfRoutePlan{}, fmt.Errorf("syscall name %q has ids %d and %d", syscall.Name, previous, id)
		}
		ids[syscall.Name] = id
		plan.enter[id] = enterProgNoPayload
		plan.exit[id] = exitProgGeneric
		capability, ok := capabilities[syscall.Name]
		if !ok {
			continue
		}
		if capability.enterSlot != 0 {
			plan.enter[id] = capability.enterSlot
		}
		if capability.exitSlot != 0 {
			plan.exit[id] = capability.exitSlot
		}
	}
	return plan, nil
}

func validateBPFRouteCapabilities(capabilities map[string]bpfRouteCapability) error {
	for name, capability := range capabilities {
		if name == "" {
			return fmt.Errorf("BPF route capability has empty syscall name")
		}
		if capability.enterSlot != 0 {
			if _, ok := bpfTailCallProgramBySlot(bpfEnterProgramCatalog, capability.enterSlot); !ok {
				return fmt.Errorf("unknown BPF enter route slot %d for syscall %q", capability.enterSlot, name)
			}
		}
		if capability.exitSlot != 0 {
			if _, ok := bpfTailCallProgramBySlot(bpfExitProgramCatalog, capability.exitSlot); !ok {
				return fmt.Errorf("unknown BPF exit route slot %d for syscall %q", capability.exitSlot, name)
			}
		}
	}
	return nil
}

func configureBPFRouteMaps(
	maps bpfMapProvider,
	programs bpfProgramProvider,
	plan bpfRoutePlan,
) error {
	if maps == nil {
		return fmt.Errorf("BPF route maps are unavailable")
	}
	enterRoutes := maps.coreMap(bpfMapEnterRoutes)
	exitRoutes := maps.coreMap(bpfMapExitRoutes)
	if enterRoutes == nil || exitRoutes == nil {
		return fmt.Errorf("BPF route maps are unavailable")
	}
	enterPrograms := routePrograms(enterProgArrayEntries(programs))
	if err := putBPFRouteEntries(bpfMapEnterRoutes, enterRoutes, plan.enter, enterPrograms); err != nil {
		return err
	}
	exitPrograms := routePrograms(exitProgArrayEntries(programs))
	return putBPFRouteEntries(bpfMapExitRoutes, exitRoutes, plan.exit, exitPrograms)
}

func routePrograms(entries []progArrayEntry) map[uint32]*ebpf.Program {
	programs := make(map[uint32]*ebpf.Program, len(entries))
	for _, entry := range entries {
		programs[entry.index] = entry.prog
	}
	return programs
}

func putBPFRouteEntries(name string, writer progArrayWriter, routes map[uint32]uint32, programs map[uint32]*ebpf.Program) error {
	ids := make([]uint32, 0, len(routes))
	for id := range routes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		slot := routes[id]
		program := programs[slot]
		if program == nil {
			return fmt.Errorf("%s[%d]: nil handler for slot %d", name, id, slot)
		}
		if err := writer.Put(id, program); err != nil {
			return fmt.Errorf("%s[%d]: %w", name, id, err)
		}
	}
	return nil
}
