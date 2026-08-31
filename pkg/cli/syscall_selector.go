package cli

import (
	"regexp"
	"runtime"
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

type syscallSelectorTerm struct {
	expression string
	diagnostic string
	optional   bool
	active     bool
}

func parseSyscallSelector(value string) syscallSelector {
	originalValue := value
	selector := syscallSelector{names: make(map[string]bool)}
	selector.negated = strings.HasPrefix(value, "!")
	value = strings.TrimPrefix(value, "!")
	if strings.Trim(value, ",") == "" {
		failOption("invalid system call '%s'", originalValue)
	}
	tokens := strings.FieldsFunc(value, func(separator rune) bool {
		return separator == ','
	})
	for _, token := range tokens {
		selector.add(parseSyscallSelectorTerm(token), len(tokens))
	}
	return selector
}

func parseSyscallSelectorTerm(token string) syscallSelectorTerm {
	term := syscallSelectorTerm{
		diagnostic: token,
		optional:   strings.HasPrefix(token, "?"),
		active:     true,
	}
	term.expression = strings.TrimPrefix(token, "?")
	separator := strings.LastIndexByte(term.expression, '@')
	if separator < 0 {
		return term
	}
	personality := term.expression[separator+1:]
	if !supportedSyscallPersonality(personality) {
		failOption("incorrect personality designator '%s' in qualification '%s'", personality, term.diagnostic)
	}
	term.expression = term.expression[:separator]
	term.active = personality == nativeSyscallPersonality()
	return term
}

func supportedSyscallPersonality(personality string) bool {
	switch runtime.GOARCH {
	case "amd64":
		return personality == "64" || personality == "32" || personality == "x32"
	case "arm64", "ppc64", "ppc64le", "s390x", "sparc64":
		return personality == "64" || personality == "32"
	default:
		return personality == nativeSyscallPersonality()
	}
}

func nativeSyscallPersonality() string {
	return strconv.Itoa(strconv.IntSize)
}

func (selector *syscallSelector) add(term syscallSelectorTerm, tokenCount int) {
	switch term.expression {
	case "all", "%all":
		if term.active {
			selector.all = true
		}
	case "none":
		if tokenCount == 1 {
			return
		}
		selector.rejectInvalid(term)
	default:
		target := selector
		if !term.active {
			target = &syscallSelector{names: make(map[string]bool)}
		}
		if !target.addExpression(term.expression) {
			selector.rejectInvalid(term)
		}
	}
}

func (selector *syscallSelector) rejectInvalid(term syscallSelectorTerm) {
	if !term.optional {
		failOption("invalid system call '%s'", term.diagnostic)
	}
}

func (selector *syscallSelector) addExpression(token string) bool {
	if strings.HasPrefix(token, "/") {
		pattern := strings.TrimPrefix(token, "/")
		if strings.HasPrefix(pattern, "{") {
			failOption("regcomp: %s: invalid repetition operator", pattern)
		}
		expression, err := regexp.Compile(pattern)
		if err != nil {
			failOption("regcomp: %s: %v", pattern, err)
		}
		if !regexpMatchesSyscall(expression) {
			return false
		}
		selector.regexps = append(selector.regexps, expression)
		return true
	}
	if addSyscallClass(selector.names, token) {
		return true
	}
	if addSyscallNumber(selector.names, token) {
		return true
	}
	return addSyscallName(selector.names, token)
}

func regexpMatchesSyscall(expression *regexp.Regexp) bool {
	for _, syscall := range meta.SyscallTable {
		if expression.MatchString(syscall.Name) {
			return true
		}
	}
	return false
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
	syscall, ok := meta.SyscallTable[uint32(number)]
	if !ok {
		return false
	}
	names[syscall.Name] = true
	return true
}

func addSyscallName(names map[string]bool, name string) bool {
	for _, syscall := range meta.SyscallTable {
		if syscall.Name != name {
			continue
		}
		names[name] = true
		addTraceAliasesTo(names, name)
		return true
	}
	return false
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
