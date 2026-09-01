package main

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/cilium/ebpf"

	"strace-go/pkg/meta"
)

type syscallFilterInput struct {
	names      map[string]bool
	regexps    []*regexp.Regexp
	configured bool
	matchesAll bool
	negated    bool
}

type syscallFilterPlan struct {
	enabled bool
	negated bool
	ids     []uint32
}

type syscallFilterEntry struct {
	id       uint32
	selected uint32
}

func buildSyscallFilterPlan(input syscallFilterInput) syscallFilterPlan {
	if !input.configured || input.matchesAll {
		return syscallFilterPlan{}
	}

	ids := make(map[uint32]bool)
	for id, sc := range meta.SyscallTable {
		if input.names[sc.Name] {
			ids[id] = true
			continue
		}
		for _, re := range input.regexps {
			if re.MatchString(sc.Name) {
				ids[id] = true
				break
			}
		}
	}

	plan := syscallFilterPlan{
		enabled: true,
		negated: input.negated,
		ids:     make([]uint32, 0, len(ids)),
	}
	for id := range ids {
		plan.ids = append(plan.ids, id)
	}
	sort.Slice(plan.ids, func(i, j int) bool {
		return plan.ids[i] < plan.ids[j]
	})
	return plan
}

// includeSyscalls keeps runtime-control syscalls observable without changing
// the user-space output selector that decides whether they are published.
func includeSyscalls(plan syscallFilterPlan, names ...string) syscallFilterPlan {
	if !plan.enabled {
		return plan
	}
	ids := make(map[uint32]bool, len(plan.ids)+len(names))
	for _, id := range plan.ids {
		ids[id] = true
	}
	for id, syscall := range meta.SyscallTable {
		if !containsString(names, syscall.Name) {
			continue
		}
		if plan.negated {
			delete(ids, id)
		} else {
			ids[id] = true
		}
	}
	plan.ids = plan.ids[:0]
	for id := range ids {
		plan.ids = append(plan.ids, id)
	}
	sort.Slice(plan.ids, func(i, j int) bool { return plan.ids[i] < plan.ids[j] })
	return plan
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// IMPACT: every known syscall gets an explicit selection value so a BPF map
// miss uniquely identifies an unknown syscall that must bypass name filters.
func materializeSyscallFilterEntries(
	plan syscallFilterPlan,
	table map[uint32]meta.Syscall,
) []syscallFilterEntry {
	if !plan.enabled {
		return nil
	}
	selected := make(map[uint32]bool, len(plan.ids))
	for _, id := range plan.ids {
		selected[id] = true
	}
	entries := make([]syscallFilterEntry, 0, len(table))
	for id := range table {
		value := uint32(0)
		if selected[id] {
			value = 1
		}
		entries = append(entries, syscallFilterEntry{id: id, selected: value})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	return entries
}

func configureSyscallFilter(plan syscallFilterPlan, maps bpfMapProvider) (uint32, error) {
	if !plan.enabled {
		return 0, nil
	}
	if maps == nil {
		return 0, fmt.Errorf("BPF syscall filter map is unavailable")
	}
	filterMap := maps.coreMap(bpfMapSyscallFilter)
	if filterMap == nil {
		return 0, fmt.Errorf("BPF syscall filter map is unavailable")
	}

	for _, entry := range materializeSyscallFilterEntries(plan, meta.SyscallTable) {
		if err := filterMap.Update(entry.id, entry.selected, ebpf.UpdateAny); err != nil {
			return 0, err
		}
	}

	cfg := uint32(bpfConfigSyscallFilter)
	if plan.negated {
		cfg |= bpfConfigSyscallFilterNegated
	}
	return cfg, nil
}
