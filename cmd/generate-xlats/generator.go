package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type xlatTableData struct {
	name    string
	prefix  string
	keys    []string
	entries map[string]string
}

func writeXlatAutoFile(out io.Writer, argXlat ArgXlatMap, xlatDir string) {
	fmt.Fprintln(out, "package meta")
	fmt.Fprintln(out, "type XlatVal struct { Val uint64; Str string }")
	fmt.Fprintln(out, "type XlatTable struct { Prefix string; Entries []XlatVal }")
	fmt.Fprintln(out, "var XlatTables = map[string]XlatTable{")
	emitted := writeUpstreamXlatTables(out, xlatDir, allowedXlatNames(argXlat))
	writeGeneratedStaticXlatTables(out, emitted, ioctlIncludePath)
	fmt.Fprintln(out, "}")
	writeSyscallArgXlatMap(out, argXlat.Syscalls)
}

func allowedXlatNames(argXlat ArgXlatMap) map[string]bool {
	allowed := make(map[string]bool)
	for _, m := range argXlat.Syscalls {
		for _, xlat := range m {
			allowed[xlat] = true
		}
	}
	for _, xlat := range alwaysAllowedXlats {
		allowed[xlat] = true
	}
	for _, xlat := range staticOnlyXlats {
		delete(allowed, xlat)
	}
	return allowed
}

func writeUpstreamXlatTables(out io.Writer, xlatDir string, allowed map[string]bool) map[string]bool {
	files, err := os.ReadDir(xlatDir)
	if err != nil {
		panic(fmt.Sprintf("failed to read xlat dir %s: %v", xlatDir, err))
	}
	emitted := make(map[string]bool)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".in") {
			continue
		}
		name := strings.TrimSuffix(f.Name(), ".in")
		if !allowed[name] {
			continue
		}
		table := buildXlatTable(xlatDir, name, f.Name())
		writeXlatTable(out, table)
		emitted[name] = true
	}
	return emitted
}

func buildXlatTable(xlatDir string, name string, fileName string) xlatTableData {
	table := xlatTableData{name: name, entries: make(map[string]string)}
	content := readXlatInput(xlatDir, name, fileName)
	cProg := newXlatCProgram(xlatDir, name)
	for _, line := range strings.Split(string(content), "\n") {
		parseXlatInputLine(line, &table, cProg)
	}
	cProg.WriteString("\treturn 0;\n}\n")
	if name == "open_resolve_flags" {
		fmt.Printf("Evaluating open_resolve_flags: %d keys\n", len(table.keys))
	}
	evaluateCConstants(name, cProg.String(), table.entries)
	applyStableXlatFallbacks(name, &table.prefix, table.entries, &table.keys)
	normalizeXlatPrefix(name, &table.prefix)
	return table
}

func readXlatInput(xlatDir string, name string, fileName string) []byte {
	content, _ := os.ReadFile(filepath.Join(xlatDir, fileName))
	if name == "madvise_cmds" {
		if extra, err := os.ReadFile(filepath.Join(xlatDir, "madvise_hppa_generic_cmds.in")); err == nil {
			content = append(append(content, '\n'), extra...)
		}
	}
	return content
}

func newXlatCProgram(xlatDir string, name string) *strings.Builder {
	cProg := &strings.Builder{}
	cProg.WriteString(xlatCIncludes)
	if name == "resources" || name == "priorities" {
		cProg.WriteString("#include <sys/resource.h>\n")
	}
	if name == "itimer_which" {
		cProg.WriteString("#include <sys/time.h>\n")
	}
	if usesQuotaXlatCDefinitions(name) {
		cProg.WriteString(quotaXlatCDefinitions)
	}
	cProg.WriteString(xlatCCompatDefines)
	hPath := filepath.Join(xlatDir, name+".h")
	if _, err := os.Stat(hPath); err == nil {
		cProg.WriteString("#define XLAT_MACROS_ONLY\n")
		cProg.WriteString(fmt.Sprintf("#include %q\n", hPath))
		cProg.WriteString("#undef XLAT_MACROS_ONLY\n")
	}
	cProg.WriteString("int main() {\n")
	return cProg
}

func usesQuotaXlatCDefinitions(name string) bool {
	switch name {
	case "quotacmds", "xfs_dqblk_flags", "xfs_quota_flags":
		return true
	default:
		return false
	}
}

func parseXlatInputLine(line string, table *xlatTableData, cProg *strings.Builder) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "#Prefix ") {
		table.prefix = strings.TrimSpace(strings.TrimPrefix(line, "#Prefix "))
	}
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "/") {
		return
	}
	parts := strings.Fields(line)
	if len(parts) < 1 || !isCIdentifier(parts[0]) {
		return
	}
	key := parts[0]
	table.keys = append(table.keys, key)
	if len(parts) >= 2 {
		if value, ok := parseXlatLiteralValue(parts[1]); ok {
			table.entries[key] = value
		}
	}
	cProg.WriteString(fmt.Sprintf("\t#if defined(%s)\n\tprintf(\"%%s %%llu\\n\", %q, (unsigned long long)%s);\n\t#endif\n", key, key, key))
}

func parseXlatLiteralValue(value string) (string, bool) {
	if !strings.HasPrefix(value, "0x") {
		value = stripIntegerSuffixes(value)
	}
	if !strings.Contains(value, "(") && !strings.Contains(value, "<<") {
		return value, true
	}
	if shifted, ok := parseSimpleShiftValue(value); ok {
		return shifted, true
	}
	return "", false
}

func parseSimpleShiftValue(value string) (string, bool) {
	cleanValue := strings.ReplaceAll(value, "ULL", "")
	cleanValue = strings.ReplaceAll(cleanValue, "UL", "")
	cleanValue = strings.ReplaceAll(cleanValue, "U", "")
	cleanValue = strings.ReplaceAll(cleanValue, "(", "")
	cleanValue = strings.ReplaceAll(cleanValue, ")", "")
	if !strings.Contains(cleanValue, "<<") {
		return "", false
	}
	parts := strings.Split(cleanValue, "<<")
	if len(parts) != 2 {
		return "", false
	}
	var base, shift uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(parts[0]), "%d", &base); err != nil {
		return "", false
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &shift); err != nil {
		return "", false
	}
	return fmt.Sprintf("%d", base<<shift), true
}

func evaluateCConstants(name string, cProg string, entries map[string]string) {
	cmd := exec.Command("gcc", "-x", "c", "-I../../strace-upstream/src", "-I../../strace-upstream/src/xlat", "-I../../strace-upstream/bundled/linux/include", "-o", "gen_xlat_tmp", "-")
	cmd.Stdin = strings.NewReader(cProg)
	if output, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("GCC failed for %s: %v\nOutput: %s\n", name, err, string(output))
		printCProgramPrefix(cProg)
		return
	}
	val, _ := exec.Command("./gen_xlat_tmp").Output()
	for _, resLine := range strings.Split(string(val), "\n") {
		resLine = strings.TrimSpace(resLine)
		parts := strings.Fields(resLine)
		if len(parts) == 2 {
			entries[parts[0]] = parts[1]
		}
	}
	os.Remove("gen_xlat_tmp")
}

func printCProgramPrefix(cProg string) {
	lines := strings.Split(cProg, "\n")
	for i := 0; i < 20 && i < len(lines); i++ {
		fmt.Println(lines[i])
	}
}

func writeXlatTable(out io.Writer, table xlatTableData) {
	fmt.Fprintf(out, "\t%q: {\n\t\tPrefix: %q,\n\t\tEntries: []XlatVal{\n", table.name, table.prefix)
	for _, key := range table.keys {
		value, ok := table.entries[key]
		if !ok || !isNumericXlatValue(value) {
			continue
		}
		if value == "0" && !keepZeroXlatValue(key) {
			continue
		}
		fmt.Fprintf(out, "\t\t\t{Val: %s, Str: %q},\n", value, key)
	}
	if table.name == "open_mode_flags" {
		writeOpenModeFlagFallbacks(out)
	}
	fmt.Fprintf(out, "\t\t},\n\t},\n")
}

func isNumericXlatValue(value string) bool {
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		return isHexNumber(value[2:])
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isHexNumber(value string) bool {
	for _, r := range value {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}
