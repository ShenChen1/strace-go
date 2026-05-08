package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Syscalls map[string]map[string]string `yaml:"syscalls"`
}

type XlatEntry struct {
	Name  string
	Value string
}

func parseInFile(path string) []XlatEntry {
	f, err := os.Open(path)
	if err != nil {
		fmt.Println("Warning: could not open", path)
		return nil
	}
	defer f.Close()

	var entries []XlatEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "/*") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 1 {
			entry := XlatEntry{Name: parts[0]}
			if len(parts) >= 2 {
				entry.Value = parts[1] // If it has a hardcoded value
			}
			entries = append(entries, entry)
		}
	}
	return entries
}

func main() {
	// 1. Load config
	configData, err := os.ReadFile("../generate-xlats/arg_xlat_map.yaml")
	if err != nil {
		panic(err)
	}

	var cfg Config
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		panic(err)
	}

	// Determine needed xlats
	neededXlats := make(map[string]bool)
	for _, args := range cfg.Syscalls {
		for _, xlatName := range args {
			neededXlats[xlatName] = true
		}
	}
	// Manually add implicit ones
	neededXlats["open_access_modes"] = true

	// 2. Parse .in files
	xlatDefs := make(map[string][]XlatEntry)
	for xlatName := range neededXlats {
		inPath := filepath.Join("..", "..", "strace-upstream", "src", "xlat", xlatName+".in")
		entries := parseInFile(inPath)
		if len(entries) > 0 {
			xlatDefs[xlatName] = entries
		}
	}

	// 3. Generate C code to extract values
	var cCode strings.Builder
	cCode.WriteString("#include <stdio.h>\n")
	cCode.WriteString("#include <fcntl.h>\n")
	cCode.WriteString("#include <unistd.h>\n")
	cCode.WriteString("#include <sys/stat.h>\n")
	cCode.WriteString("#include <sys/mman.h>\n")
	cCode.WriteString("int main() {\n")

	for _, entries := range xlatDefs {
		for _, entry := range entries {
			if entry.Value == "" {
				cCode.WriteString(fmt.Sprintf("#ifdef %s\n", entry.Name))
				cCode.WriteString(fmt.Sprintf("    printf(\"%s %%llu\\n\", (unsigned long long)%s);\n", entry.Name, entry.Name))
				cCode.WriteString("#endif\n")
			}
		}
	}
	cCode.WriteString("    return 0;\n}\n")

	cFilePath := "/tmp/extract_xlats.c"
	exePath := "/tmp/extract_xlats"
	os.WriteFile(cFilePath, []byte(cCode.String()), 0644)

	cmd := exec.Command("gcc", cFilePath, "-o", exePath)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("GCC Error: %s\n", out)
		panic(err)
	}

	runCmd := exec.Command(exePath)
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		panic(err)
	}

	extractedValues := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(runOut)))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) == 2 {
			extractedValues[parts[0]] = parts[1]
		}
	}

	// 4. Generate Go code
	var goCode strings.Builder
	goCode.WriteString("package meta\n\n")
	goCode.WriteString("type XlatVal struct {\n\tVal uint64\n\tStr string\n}\n\n")

	goCode.WriteString("var XlatTables = map[string][]XlatVal{\n")
	for xlatName, entries := range xlatDefs {
		goCode.WriteString(fmt.Sprintf("\t\"%s\": {\n", xlatName))
		for _, entry := range entries {
			val := entry.Value
			if val == "" {
				v, ok := extractedValues[entry.Name]
				if !ok {
					continue // Not defined on this system
				}
				val = v
			}
			// If hardcoded value is not numeric, we could have problems, but in access_modes it is '4' '2' etc.
			goCode.WriteString(fmt.Sprintf("\t\t{Val: %s, Str: \"%s\"},\n", val, entry.Name))
		}
		goCode.WriteString("\t},\n")
	}
	goCode.WriteString("}\n\n")

	// Generate the mapping from syscall -> arg -> xlat
	goCode.WriteString("var SyscallArgXlatMap = map[string]map[string]string{\n")
	for scName, args := range cfg.Syscalls {
		goCode.WriteString(fmt.Sprintf("\t\"%s\": {\n", scName))
		for argName, xlatName := range args {
			goCode.WriteString(fmt.Sprintf("\t\t\"%s\": \"%s\",\n", argName, xlatName))
		}
		goCode.WriteString("\t},\n")
	}
	goCode.WriteString("}\n")

	os.MkdirAll("../../pkg/meta", 0755)
	os.WriteFile("../../pkg/meta/xlat_auto.go", []byte(goCode.String()), 0644)
	fmt.Println("Generated pkg/meta/xlat_auto.go")
}
