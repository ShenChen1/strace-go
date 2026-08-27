package cli

import (
	"regexp"
	"strconv"
	"strings"

	"strace-go/pkg/meta"
)

type syscallSelector struct {
	names   map[string]bool
	regexps []*regexp.Regexp
	all     bool
	negated bool
}

func parseSyscallSelector(value string) syscallSelector {
	selector := syscallSelector{names: make(map[string]bool)}
	selector.negated = strings.HasPrefix(value, "!")
	value = strings.TrimPrefix(value, "!")
	for _, token := range strings.Split(value, ",") {
		selector.add(token)
	}
	return selector
}

func (selector *syscallSelector) add(token string) {
	switch token {
	case "all", "%all":
		selector.all = true
	case "none":
		return
	default:
		selector.addExpression(token)
	}
}

func (selector *syscallSelector) addExpression(token string) {
	if strings.HasPrefix(token, "/") {
		expression, err := regexp.Compile(strings.TrimPrefix(token, "/"))
		if err != nil {
			failOption("invalid syscall regular expression '%s': %v", token, err)
		}
		selector.regexps = append(selector.regexps, expression)
		return
	}
	if addSyscallClass(selector.names, token) {
		return
	}
	if addSyscallNumber(selector.names, token) {
		return
	}
	addSyscallName(selector.names, token)
}

func addSyscallClass(names map[string]bool, token string) bool {
	classFlag := traceClassFlag(token)
	if classFlag == "" {
		return false
	}
	for _, syscall := range meta.SyscallTable {
		if syscallHasFlag(syscall.Flags, classFlag) {
			names[syscall.Name] = true
		}
	}
	return true
}

func syscallHasFlag(flags, target string) bool {
	for _, flag := range strings.Split(flags, "|") {
		if flag == target {
			return true
		}
	}
	return false
}

func addSyscallNumber(names map[string]bool, token string) bool {
	number, err := strconv.ParseUint(token, 10, 32)
	if err != nil {
		return false
	}
	if syscall, ok := meta.SyscallTable[uint32(number)]; ok {
		names[syscall.Name] = true
	}
	return true
}

func addSyscallName(names map[string]bool, name string) {
	if name == "" {
		return
	}
	names[name] = true
	addTraceAliasesTo(names, name)
}

func (selector syscallSelector) matches(name string) bool {
	matched := selector.all || selector.names[name]
	if !matched {
		for _, expression := range selector.regexps {
			if expression.MatchString(name) {
				matched = true
				break
			}
		}
	}
	if selector.negated {
		return !matched
	}
	return matched
}

func (selector syscallSelector) explicitAllOrNone() (bool, bool) {
	if selector.all {
		return !selector.negated, true
	}
	if len(selector.names) != 0 || len(selector.regexps) != 0 {
		return false, false
	}
	return selector.negated, true
}

func materializeSyscallSelector(selector syscallSelector) map[string]bool {
	selected := make(map[string]bool)
	for _, syscall := range meta.SyscallTable {
		if selector.matches(syscall.Name) {
			selected[syscall.Name] = true
		}
	}
	if !selector.negated && !selector.all {
		for name := range selector.names {
			selected[name] = true
		}
	}
	return selected
}

func complementSyscallSet(selected map[string]bool) map[string]bool {
	complement := make(map[string]bool)
	for _, syscall := range meta.SyscallTable {
		if !selected[syscall.Name] {
			complement[syscall.Name] = true
		}
	}
	return complement
}
