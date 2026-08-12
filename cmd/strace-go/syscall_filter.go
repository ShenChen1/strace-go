package main

import (
	"regexp"
	"sort"

	"github.com/cilium/ebpf"

	"strace-go/pkg/meta"
)

type syscallFilterInput struct {
	names   map[string]bool
	regexps []*regexp.Regexp
	negated bool
}

type syscallFilterPlan struct {
	enabled bool
	negated bool
	ids     []uint32
}

func buildSyscallFilterPlan(input syscallFilterInput) syscallFilterPlan {
	if len(input.names) == 0 && len(input.regexps) == 0 {
		return syscallFilterPlan{}
	}
	if input.names["all"] || input.names["%all"] {
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

func configureSyscallFilter(plan syscallFilterPlan, objs *bpfObjects) (uint32, error) {
	if !plan.enabled {
		return 0, nil
	}

	var one uint32 = 1
	for _, id := range plan.ids {
		if err := objs.SyscallFilterMap.Update(id, one, ebpf.UpdateAny); err != nil {
			return 0, err
		}
	}

	cfg := uint32(bpfConfigSyscallFilter)
	if plan.negated {
		cfg |= bpfConfigSyscallFilterNegated
	}
	return cfg, nil
}
