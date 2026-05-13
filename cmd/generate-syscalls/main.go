package main

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type CaptureRead struct {
	Arg    int    `yaml:"arg"`
	Size   int    `yaml:"size"`
	Offset int    `yaml:"offset"`
	Type   string `yaml:"type"` // "string" or "raw"
}

type CapturePoint struct {
	PtrArg *int          `yaml:"ptr_arg,omitempty"`
	Reads  []CaptureRead `yaml:"reads"`
}

type CaptureRule struct {
	Syscalls []string     `yaml:"syscalls"`
	Enter    CapturePoint `yaml:"enter"`
	Exit     CapturePoint `yaml:"exit"`
}

type CaptureConfig struct {
	Rules []CaptureRule `yaml:"rules"`
}

var globalConfig CaptureConfig

func loadCaptureRules() {
	paths := []string{"capture_rules.yaml", "../generate-syscalls/capture_rules.yaml", "cmd/generate-syscalls/capture_rules.yaml"}
	var f *os.File
	var err error
	for _, p := range paths {
		f, err = os.Open(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Fatalf("could not find capture_rules.yaml in any of %v", paths)
	}
	defer f.Close()
	if err := yaml.NewDecoder(f).Decode(&globalConfig); err != nil {
		log.Fatalf("decode capture_rules.yaml: %v", err)
	}
}

// SyscallMeta holds the metadata for one syscall.
type SyscallMeta struct {
	Name     string
	Args     []string
	ArgTypes []string
}

func formatStringSlice(s []string) string {
	res := []string{}
	for _, x := range s {
		res = append(res, fmt.Sprintf("%q", x))
	}
	return strings.Join(res, ", ")
}

func main() {
	loadCaptureRules()
	// --- Step 1: Parse syscallent.h for ID → name + argc ---
	syscallentPath := "../../strace-upstream/src/linux/x86_64/syscallent.h"
	entries, err := parseSyscallent(syscallentPath)
	if err != nil {
		log.Fatalf("parse syscallent.h: %v", err)
	}
	fmt.Fprintf(os.Stderr, "[generate-syscalls] parsed %d entries from syscallent.h\n", len(entries))

	// --- Step 2: Load BTF signatures ---
	btfSyscalls, err := loadBTFSyscalls()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[generate-syscalls] WARNING: BTF unavailable (%v), using overrides only\n", err)
		btfSyscalls = make(map[string]SyscallMeta)
	} else {
		fmt.Fprintf(os.Stderr, "[generate-syscalls] loaded %d signatures from BTF\n", len(btfSyscalls))
	}

	// --- Step 3: Merge into final table ---
	// Priority: manualOverrides > BTF (with name mapping) > fallback (argc × unsigned long)
	scTable := make(map[int]SyscallMeta)

	for _, ent := range entries {
		name := ent.Name

		// Check manual overrides first (highest priority)
		if m, ok := manualOverrides[name]; ok {
			scTable[ent.ID] = m
			continue
		}

		// Check BTF — try direct name first, then reverse name mapping
		if m, ok := findBTFMeta(btfSyscalls, name); ok {
			m.Name = name // Ensure syscallent name is used
			scTable[ent.ID] = m
			continue
		}

		// Fallback: generate generic args from argc
		scTable[ent.ID] = makeGenericMeta(name, ent.Argc)
	}

	// Zero-arg syscalls: clean up the "__unused" from BTF
	for id, m := range scTable {
		if len(m.Args) == 1 && m.Args[0] == "__unused" {
			m.Args = []string{}
			m.ArgTypes = []string{}
			scTable[id] = m
		}
	}

	fmt.Fprintf(os.Stderr, "[generate-syscalls] final table: %d syscalls\n", len(scTable))

	// --- Step 4: Write syscall_table.go ---
	writeGoTable(scTable)

	// --- Step 5: Write syscall_capture.h ---
	writeBPFCapture(scTable)
}

// findBTFMeta looks up a syscall in the BTF map, handling name remapping.
func findBTFMeta(btfMap map[string]SyscallMeta, syscallName string) (SyscallMeta, bool) {
	// Direct lookup
	if m, ok := btfMap[syscallName]; ok {
		return m, true
	}
	// Reverse lookup via btfNameToSyscallent
	for btfName, entName := range btfNameToSyscallent {
		if entName == syscallName {
			if m, ok := btfMap[btfName]; ok {
				return m, true
			}
		}
	}
	return SyscallMeta{}, false
}

// makeGenericMeta creates a fallback SyscallMeta with argc unnamed args.
func makeGenericMeta(name string, argc int) SyscallMeta {
	if argc == 0 {
		return SyscallMeta{Name: name}
	}
	argNames := []string{"arg0", "arg1", "arg2", "arg3", "arg4", "arg5"}
	args := make([]string, argc)
	types := make([]string, argc)
	for i := 0; i < argc && i < 6; i++ {
		args[i] = argNames[i]
		types[i] = "unsigned long"
	}
	return SyscallMeta{Name: name, Args: args, ArgTypes: types}
}

func writeGoTable(scTable map[int]SyscallMeta) {
	f, err := os.Create("../../pkg/meta/syscall_table.go")
	if err != nil {
		log.Fatalf("create syscall_table.go: %v", err)
	}
	defer f.Close()

	fmt.Fprintln(f, "package meta")
	fmt.Fprintln(f, "type Syscall struct { Name string; Args []string; ArgTypes []string }")
	fmt.Fprintln(f, "var SyscallTable = map[uint32]Syscall{")

	ids := sortedKeys(scTable)
	for _, id := range ids {
		m := scTable[id]
		fmt.Fprintf(f, "\t%d: {Name: %q, Args: []string{%s}, ArgTypes: []string{%s}},\n",
			id, m.Name, formatStringSlice(m.Args), formatStringSlice(m.ArgTypes))
	}
	fmt.Fprintln(f, "}")
}

// writeBPFCapture generates syscall_capture.h with CAPTURE_ARGS_ENTER/EXIT macros.
// This preserves the existing BPF capture logic for already-handled syscalls
// and does NOT add BPF capture for newly-discovered syscalls (they use procmem fallback).
func writeBPFCapture(scTable map[int]SyscallMeta) {
	c, err := os.Create("../../bpf/syscall_capture.h")
	if err != nil {
		log.Fatalf("create syscall_capture.h: %v", err)
	}
	defer c.Close()

	ids := sortedKeys(scTable)

	// --- CAPTURE_ARGS_ENTER ---
	fmt.Fprintln(c, "#define CAPTURE_ARGS_ENTER(id, e) switch(id) { \\")
	for _, id := range ids {
		m := scTable[id]
		n := m.Name
		enter := bpfEnterCapture(n, m)
		if enter == "" {
			continue
		}
		fmt.Fprintf(c, "\t\tcase %d: /* %s */ \\\n", id, n)
		fmt.Fprint(c, enter)
		fmt.Fprintln(c, "\t\t\tbreak; \\")
	}
	fmt.Fprintln(c, "\t}")

	// --- CAPTURE_ARGS_EXIT ---
	fmt.Fprintln(c, "#define CAPTURE_ARGS_EXIT(id, e) switch(id) { \\")
	for _, id := range ids {
		m := scTable[id]
		n := m.Name
		exit := bpfExitCapture(n)
		if exit == "" {
			continue
		}
		fmt.Fprintf(c, "\t\tcase %d: /* %s */ \\\n", id, n)
		fmt.Fprint(c, exit)
		fmt.Fprintln(c, "\t\t\tbreak; \\")
	}
	fmt.Fprintln(c, "\t}")
}

// bpfEnterCapture returns the BPF capture code for sys_enter, or "" if none needed.
func bpfEnterCapture(name string, m SyscallMeta) string {
	for _, rule := range globalConfig.Rules {
		for _, sc := range rule.Syscalls {
			if sc == name {
				return generateBPFCode(rule.Enter, "enter")
			}
		}
	}
	return ""
}

// bpfExitCapture returns the BPF capture code for sys_exit, or "" if none needed.
func bpfExitCapture(name string) string {
	for _, rule := range globalConfig.Rules {
		for _, sc := range rule.Syscalls {
			if sc == name {
				return generateBPFCode(rule.Exit, "exit")
			}
		}
	}
	return ""
}

func generateBPFCode(p CapturePoint, suffix string) string {
	res := ""
	if p.PtrArg != nil {
		res += fmt.Sprintf("\t\t\t(e)->ptr = (e)->args[%d]; \\\n", *p.PtrArg)
	}
	for _, r := range p.Reads {
		fn := "bpf_probe_read_user"
		if r.Type == "string" {
			fn = "bpf_probe_read_user_str"
		}
		buf := "(e)->str_arg"
		if r.Offset != 0 {
			buf += fmt.Sprintf(" + %d", r.Offset)
		}
		res += fmt.Sprintf("\t\t\te->probe_ret_%s = %s(%s, %d, (void *)(e)->args[%d]); \\\n", suffix, fn, buf, r.Size, r.Arg)
	}
	return res
}
func sortedKeys(m map[int]SyscallMeta) []int {
	ids := make([]int, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}
