package main

import (
	"fmt"
	"sort"
)

var captureHandlerFamilies = map[string]struct{}{
	"bpfHandlerEnterGenericFamily":    {},
	"bpfHandlerEnterPayloadFamily":    {},
	"bpfHandlerEnterPathFamily":       {},
	"bpfHandlerEnterMemoryFamily":     {},
	"bpfHandlerEnterControlFamily":    {},
	"bpfHandlerEnterStructuredFamily": {},
	"bpfHandlerExitFamily":            {},
	"bpfHandlerRecvmsgFamily":         {},
}

func validateCaptureManifest(manifest captureManifest) error {
	if manifest.routeMapMaxEntries == 0 {
		return fmt.Errorf("route map capacity is zero")
	}
	programs, err := validateCapturePrograms(manifest.programs)
	if err != nil {
		return err
	}
	if err := validateCaptureRoutes(manifest.routes, programs); err != nil {
		return err
	}
	if err := validateCaptureAuxRoots(manifest.auxRoots, programs, manifest.routes); err != nil {
		return err
	}
	return validateCaptureDependencies(manifest.programs, programs)
}

func validateCapturePrograms(specs []captureProgramSpec) (map[string]captureProgramSpec, error) {
	programs := make(map[string]captureProgramSpec, len(specs))
	seenGo := make(map[string]struct{}, len(specs))
	seenC := make(map[string]struct{}, len(specs))
	seenSlots := make(map[captureProgramArray]map[uint32]struct{})
	for index, spec := range specs {
		if spec.programName == "" {
			return nil, fmt.Errorf("program %d has empty ELF name", index)
		}
		if _, exists := programs[spec.programName]; exists {
			return nil, fmt.Errorf("duplicate ELF program %q", spec.programName)
		}
		if spec.familyGoName == "" {
			return nil, fmt.Errorf("program %q has empty handler family", spec.programName)
		}
		if _, ok := captureHandlerFamilies[spec.familyGoName]; !ok {
			return nil, fmt.Errorf("program %q has unknown handler family %q", spec.programName, spec.familyGoName)
		}
		if spec.kind == captureProgramTailCall {
			if spec.goName == "" || spec.cName == "" {
				return nil, fmt.Errorf("tail-call program %q has incomplete slot names", spec.programName)
			}
			if _, exists := seenGo[spec.goName]; exists {
				return nil, fmt.Errorf("duplicate Go slot name %q", spec.goName)
			}
			if _, exists := seenC[spec.cName]; exists {
				return nil, fmt.Errorf("duplicate C slot name %q", spec.cName)
			}
			seenGo[spec.goName] = struct{}{}
			seenC[spec.cName] = struct{}{}
			if seenSlots[spec.array] == nil {
				seenSlots[spec.array] = make(map[uint32]struct{})
			}
			if _, exists := seenSlots[spec.array][spec.slot]; exists {
				return nil, fmt.Errorf("duplicate slot %d in %s array", spec.slot, spec.array)
			}
			seenSlots[spec.array][spec.slot] = struct{}{}
		} else if spec.kind == captureProgramStandalone {
			if spec.array != "" || spec.goName != "" || spec.cName != "" {
				return nil, fmt.Errorf("standalone program %q has tail-call slot metadata", spec.programName)
			}
		} else {
			return nil, fmt.Errorf("program %q has unknown kind %q", spec.programName, spec.kind)
		}
		programs[spec.programName] = spec
	}
	if err := validateDenseProgramArrays(seenSlots); err != nil {
		return nil, err
	}
	return programs, nil
}

func validateDenseProgramArrays(slots map[captureProgramArray]map[uint32]struct{}) error {
	for _, array := range []captureProgramArray{
		captureProgramArrayEnter,
		captureProgramArrayExit,
		captureProgramArrayRecvmsg,
		captureProgramArrayMmsg,
	} {
		seen := slots[array]
		if len(seen) == 0 {
			return fmt.Errorf("%s program array is empty", array)
		}
		start := uint32(0)
		if array == captureProgramArrayEnter {
			start = 1
		}
		max := start
		for slot := range seen {
			if slot > max {
				max = slot
			}
		}
		for slot := start; slot <= max; slot++ {
			if _, ok := seen[slot]; !ok {
				return fmt.Errorf("%s program array has slot gap at %d", array, slot)
			}
		}
	}
	return nil
}

func validateCaptureRoutes(specs []captureRouteSpec, programs map[string]captureProgramSpec) error {
	seen := make(map[string]struct{}, len(specs))
	for _, route := range specs {
		if route.syscallName == "" {
			return fmt.Errorf("route has empty syscall name")
		}
		if _, exists := seen[route.syscallName]; exists {
			return fmt.Errorf("duplicate syscall route %q", route.syscallName)
		}
		seen[route.syscallName] = struct{}{}
		if err := validateRouteProgram(route.syscallName, "enter", route.enterProgram, captureProgramArrayEnter, programs); err != nil {
			return err
		}
		if err := validateRouteProgram(route.syscallName, "exit", route.exitProgram, captureProgramArrayExit, programs); err != nil {
			return err
		}
		if route.standaloneExitElision {
			if route.enterProgram != "" || route.exitProgram == "" {
				return fmt.Errorf("route %q has invalid standalone exit elision", route.syscallName)
			}
			if programs[route.exitProgram].slot == 0 {
				return fmt.Errorf("route %q elides enter with generic exit", route.syscallName)
			}
		}
	}
	return nil
}

func validateRouteProgram(
	syscallName string,
	direction string,
	programName string,
	wantArray captureProgramArray,
	programs map[string]captureProgramSpec,
) error {
	if programName == "" {
		return nil
	}
	spec, ok := programs[programName]
	if !ok {
		return fmt.Errorf("route %q references unknown %s program %q", syscallName, direction, programName)
	}
	if spec.kind != captureProgramTailCall || spec.array != wantArray {
		return fmt.Errorf("route %q references non-%s program %q", syscallName, direction, programName)
	}
	if !spec.direct {
		return fmt.Errorf("route %q references non-direct %s program %q", syscallName, direction, programName)
	}
	return nil
}

func validateCaptureAuxRoots(
	roots []captureAuxRootSpec,
	programs map[string]captureProgramSpec,
	routes []captureRouteSpec,
) error {
	routeNames := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		routeNames[route.syscallName] = struct{}{}
	}
	seen := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		if _, exists := routeNames[root.syscallName]; !exists {
			return fmt.Errorf("aux root %q has no syscall route", root.syscallName)
		}
		if _, exists := seen[root.syscallName]; exists {
			return fmt.Errorf("duplicate aux root %q", root.syscallName)
		}
		seen[root.syscallName] = struct{}{}
		for _, name := range root.programs {
			spec, ok := programs[name]
			if !ok || spec.kind != captureProgramStandalone {
				return fmt.Errorf("aux root %q references invalid standalone program %q", root.syscallName, name)
			}
		}
		for _, ref := range root.programRefs {
			if err := validateProgramRef(ref, programs); err != nil {
				return fmt.Errorf("aux root %q: %w", root.syscallName, err)
			}
		}
	}
	return nil
}

func validateCaptureDependencies(specs []captureProgramSpec, programs map[string]captureProgramSpec) error {
	for _, spec := range specs {
		for _, ref := range spec.dependencies {
			if err := validateProgramRef(ref, programs); err != nil {
				return fmt.Errorf("program %q: %w", spec.programName, err)
			}
			if ref.array != spec.array {
				return fmt.Errorf("program %q dependency %q crosses arrays", spec.programName, ref.program)
			}
		}
	}
	state := make(map[string]uint8, len(programs))
	var visit func(string) error
	visit = func(name string) error {
		if state[name] == 1 {
			return fmt.Errorf("program dependency cycle at %q", name)
		}
		if state[name] == 2 {
			return nil
		}
		state[name] = 1
		for _, ref := range programs[name].dependencies {
			if err := visit(ref.program); err != nil {
				return err
			}
		}
		state[name] = 2
		return nil
	}
	for name := range programs {
		if err := visit(name); err != nil {
			return err
		}
	}
	return nil
}

func validateProgramRef(ref captureProgramRef, programs map[string]captureProgramSpec) error {
	spec, ok := programs[ref.program]
	if !ok {
		return fmt.Errorf("unknown dependency program %q", ref.program)
	}
	if spec.kind != captureProgramTailCall || spec.array != ref.array {
		return fmt.Errorf("dependency %q has wrong program array", ref.program)
	}
	return nil
}

func sortedProgramSpecs(specs []captureProgramSpec) []captureProgramSpec {
	result := append([]captureProgramSpec(nil), specs...)
	sort.Slice(result, func(i, j int) bool {
		if result[i].array != result[j].array {
			return result[i].array < result[j].array
		}
		return result[i].slot < result[j].slot
	})
	return result
}

func sortedRouteSpecs(specs []captureRouteSpec) []captureRouteSpec {
	result := append([]captureRouteSpec(nil), specs...)
	sort.Slice(result, func(i, j int) bool { return result[i].syscallName < result[j].syscallName })
	return result
}

func sortedAuxRootSpecs(specs []captureAuxRootSpec) []captureAuxRootSpec {
	result := append([]captureAuxRootSpec(nil), specs...)
	sort.Slice(result, func(i, j int) bool { return result[i].syscallName < result[j].syscallName })
	return result
}
