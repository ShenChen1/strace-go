package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Arg struct {
	Type string
	Name string
}

type Syscall struct {
	ID   int
	Name string
	Args []Arg
}

func main() {
	entries, err := os.ReadDir("/sys/kernel/tracing/events/syscalls")
	if err != nil {
		fmt.Printf("Failed to read syscalls dir: %v\n", err)
		os.Exit(1)
	}

	syscalls := make(map[string]*Syscall)
	reField := regexp.MustCompile(`field:(.+) ([a-zA-Z0-9_]+);`)

	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "sys_enter_") { continue }
		name := strings.TrimPrefix(entry.Name(), "sys_enter_")
		formatPath := filepath.Join("/sys/kernel/tracing/events/syscalls", entry.Name(), "format")
		f, err := os.Open(formatPath)
		if err != nil { continue }
		sc := &Syscall{Name: name}
		scanner := bufio.NewScanner(f)
		isFormat := false
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "format:") { isFormat = true; continue }
			if !isFormat { continue }
			if strings.Contains(line, "__syscall_nr") { continue }
			matches := reField.FindStringSubmatch(line)
			if len(matches) == 3 {
				typ := strings.TrimSpace(matches[1]); argName := strings.TrimSpace(matches[2])
				if strings.HasPrefix(argName, "common_") { continue }
				sc.Args = append(sc.Args, Arg{Type: typ, Name: argName})
			}
		}
		f.Close()
		syscalls[name] = sc
	}

	syscallMap := make(map[string]int)
	cmd := exec.Command("sh", "-c", "echo '#include <sys/syscall.h>' | gcc -E -dM -")
	out, err := cmd.Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "#define __NR_") {
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					name := strings.TrimPrefix(parts[1], "__NR_")
					id, err := strconv.Atoi(parts[2])
					if err == nil {
						syscallMap[name] = id
					}
				}
			}
		}
	} else {
		fmt.Printf("Warning: failed to extract syscall IDs dynamically: %v\n", err)
	}

	goFile, _ := os.Create("../../pkg/meta/syscall_table.go")
	fmt.Fprintln(goFile, "package meta\n\ntype SyscallMeta struct { Name string; Args []string; ArgTypes []string }\n")
	fmt.Fprintln(goFile, "var SyscallTable = map[uint32]SyscallMeta{")
	keys := make([]string, 0, len(syscalls))
	for k := range syscalls { keys = append(keys, k) }
	sort.Strings(keys)
	for _, name := range keys {
		sc := syscalls[name]; id, ok := syscallMap[name]
		if !ok {
			// Handle aliases
			if strings.HasPrefix(name, "new") {
				baseName := strings.TrimPrefix(name, "new")
				if id2, ok2 := syscallMap[baseName]; ok2 {
					id = id2
					name = baseName // Use the standard name
					ok = true
				}
			}
		}
		if !ok { continue }
		fmt.Fprintf(goFile, "\t%d: {Name: \"%s\", Args: []string{", id, name)
		for _, a := range sc.Args { fmt.Fprintf(goFile, "\"%s\", ", a.Name) }
		fmt.Fprint(goFile, "}, ArgTypes: []string{")
		for _, a := range sc.Args { fmt.Fprintf(goFile, "\"%s\", ", a.Type) }
		fmt.Fprintln(goFile, "}},")
	}
	fmt.Fprintln(goFile, "}")
	goFile.Close()

	cFile, _ := os.Create("../../bpf/syscall_capture.h")
	fmt.Fprintln(cFile, "#define CAPTURE_ARGS(sys_id, e) \\")
	fmt.Fprintln(cFile, "\tswitch (sys_id) { \\")
	for _, name := range keys {
		sc := syscalls[name]; id, ok := syscallMap[name]
		if !ok {
			if strings.HasPrefix(name, "new") {
				baseName := strings.TrimPrefix(name, "new")
				if id2, ok2 := syscallMap[baseName]; ok2 {
					id = id2
					name = baseName
					ok = true
				}
			}
		}
		if !ok { continue }
		
		ptrIndices := []int{}
		for i, a := range sc.Args {
			if strings.Contains(a.Type, "*") {
				ptrIndices = append(ptrIndices, i)
				break // Only capture the first pointer to match strace.c
			}
		}

		if len(ptrIndices) > 0 {
			fmt.Fprintf(cFile, "\t\tcase %d: /* %s */ \\\n", id, name)
			idx := ptrIndices[0]
			fmt.Fprintf(cFile, "\t\t\t(e)->ptr = (e)->args[%d]; \\\n", idx)
			isStr := strings.Contains(sc.Args[idx].Type, "char")
			if isStr {
				fmt.Fprintf(cFile, "\t\t\tbpf_probe_read_user_str((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[%d]); \\\n", idx)
			} else {
				fmt.Fprintf(cFile, "\t\t\tbpf_probe_read_user((e)->str_arg, sizeof((e)->str_arg), (void *)(e)->args[%d]); \\\n", idx)
			}
			fmt.Fprintln(cFile, "\t\t\tbreak; \\")
		}
	}
	fmt.Fprintln(cFile, "\t}")
	cFile.Close()

	fmt.Println("Generated syscall_table.go and syscall_capture.h")
}
