package main

import (
	"sort"

	"github.com/cilium/ebpf"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

type syscallFilterPlan struct {
	enabled bool
	negated bool
	ids     []uint32
}

func buildSyscallFilterPlan(opts *cli.Options) syscallFilterPlan {
	if opts == nil || (len(opts.TraceSyscalls) == 0 && len(opts.TraceSyscallRegexps) == 0) {
		return syscallFilterPlan{}
	}
	if opts.TraceSyscalls["all"] || opts.TraceSyscalls["%all"] {
		return syscallFilterPlan{}
	}

	ids := make(map[uint32]bool)
	for id, sc := range meta.SyscallTable {
		if opts.TraceSyscalls[sc.Name] {
			ids[id] = true
			continue
		}
		for _, re := range opts.TraceSyscallRegexps {
			if re.MatchString(sc.Name) {
				ids[id] = true
				break
			}
		}
	}

	plan := syscallFilterPlan{
		enabled: true,
		negated: opts.TraceSetIsNegated,
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

func configureSyscallFilter(opts *cli.Options, objs *bpfObjects) (uint32, error) {
	plan := buildSyscallFilterPlan(opts)
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
