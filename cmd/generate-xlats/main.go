package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"gopkg.in/yaml.v3"
)

type ArgXlatMap struct {
	Syscalls map[string]map[string]string `yaml:"syscalls"`
}

func main() {
	xlatDir := "/opt/strace-go/strace-upstream/src/xlat"
	argXlatPath := "../generate-xlats/arg_xlat_map.yaml"
	if _, err := os.Stat(argXlatPath); err != nil {
		argXlatPath = "arg_xlat_map.yaml"
	}
	argXlatData, _ := os.ReadFile(argXlatPath)
	var argXlat ArgXlatMap
	yaml.Unmarshal(argXlatData, &argXlat)

	out, _ := os.Create("../../pkg/meta/xlat_auto.go")
	fmt.Fprintln(out, "package meta")
	fmt.Fprintln(out, "type XlatVal struct { Val uint64; Str string }")
	fmt.Fprintln(out, "type XlatTable struct { Entries []XlatVal; Prefix string }")
	fmt.Fprintln(out, "var XlatTables = map[string]XlatTable{")

	allowedXlats := make(map[string]bool)
	for _, m := range argXlat.Syscalls {
		for _, xlatName := range m {
			allowedXlats[xlatName] = true
		}
	}
	// Manual additions
	allowedXlats["open_access_modes"] = true
	allowedXlats["addrfams"] = true
	allowedXlats["whence"] = true
	allowedXlats["adjtimex_status"] = true

	files, _ := os.ReadDir(xlatDir)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".in") { continue }
		name := strings.TrimSuffix(f.Name(), ".in")
		if !allowedXlats[name] { continue }
		content, _ := os.ReadFile(filepath.Join(xlatDir, f.Name()))
		prefix := ""
		keys := []string{}
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#Prefix ") { prefix = strings.TrimSpace(strings.TrimPrefix(line, "#Prefix ")) }
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "/") { continue }
			parts := strings.Fields(line)
			if len(parts) >= 1 { keys = append(keys, parts[0]) }
		}
		fmt.Fprintf(out, "\t%q: {\n\t\tPrefix: %q,\n\t\tEntries: []XlatVal{\n", name, prefix)
		cProg := strings.Builder{}
		cProg.WriteString("#define _GNU_SOURCE\n#include <stdio.h>\n#include <fcntl.h>\n#include <sys/types.h>\n#include <sys/socket.h>\n#include <sys/un.h>\n#include <linux/prctl.h>\n#include <asm/prctl.h>\n#include <linux/stat.h>\n#include <linux/fs.h>\n#include <linux/timex.h>\n#include <poll.h>\n#include <sys/epoll.h>\n#include <linux/bpf.h>\n#include <time.h>\n#include <asm/termios.h>\n")
		cProg.WriteString("#ifndef ARCH_GET_CPUID\n#define ARCH_GET_CPUID 0x1011\n#endif\n#ifndef ARCH_SET_CPUID\n#define ARCH_SET_CPUID 0x1012\n#endif\n")
		cProg.WriteString("#ifndef XFEATURE_FP\n#define XFEATURE_FP 0\n#endif\n#ifndef XFEATURE_SSE\n#define XFEATURE_SSE 1\n#endif\n#ifndef XFEATURE_YMM\n#define XFEATURE_YMM 2\n#endif\n#ifndef XFEATURE_PT_UNIMPLEMENTED_SO_FAR\n#define XFEATURE_PT_UNIMPLEMENTED_SO_FAR 8\n#endif\n")
		cProg.WriteString("int main() {\n")
		for _, k := range keys { cProg.WriteString(fmt.Sprintf("\t#ifdef %s\n\tprintf(\"%s %%lu\\n\", (unsigned long)%s);\n\t#endif\n", k, k, k)) }
		cProg.WriteString("\treturn 0;\n}\n")
		cmd := exec.Command("gcc", "-x", "c", "-o", "gen_xlat_tmp", "-")
		cmd.Stdin = strings.NewReader(cProg.String())
		if err := cmd.Run(); err == nil {
			val, _ := exec.Command("./gen_xlat_tmp").Output()
			for _, resLine := range strings.Split(string(val), "\n") {
				resLine = strings.TrimSpace(resLine)
				if resLine == "" { continue }
				parts := strings.Fields(resLine)
				if len(parts) == 2 {
					str := parts[0]; v := parts[1]
					if v == "0" && str != "O_RDONLY" && str != "F_OK" && str != "AF_UNSPEC" && str != "SEEK_SET" && str != "XFEATURE_FP" && str != "BPF_MAP_CREATE" && str != "CLOCK_REALTIME" { continue }
					fmt.Fprintf(out, "\t\t\t{Val: %s, Str: %q},\n", v, str)
				}
			}
			os.Remove("gen_xlat_tmp")
		}
		if name == "open_mode_flags" {
			fmt.Fprintf(out, "\t\t\t{Val: 16384, Str: \"O_DIRECT\"},\n")
			fmt.Fprintf(out, "\t\t\t{Val: 4259840, Str: \"O_TMPFILE\"},\n")
			fmt.Fprintf(out, "\t\t\t{Val: 1052672, Str: \"O_SYNC\"},\n")
			fmt.Fprintf(out, "\t\t\t{Val: 4194304, Str: \"__O_TMPFILE\"},\n")
			fmt.Fprintf(out, "\t\t\t{Val: 1048576, Str: \"__O_SYNC\"},\n")
			fmt.Fprintf(out, "\t\t\t{Val: 32768, Str: \"O_LARGEFILE\"},\n")
		}
		fmt.Fprintf(out, "\t\t},\n\t},\n")
	}
	if !allowedXlats["x86_xfeatures"] {
		fmt.Fprintf(out, "\t%q: {\n\t\tPrefix: %q,\n\t\tEntries: []XlatVal{\n", "x86_xfeatures", "")
		fmt.Fprintf(out, "\t\t\t{Val: 0x1, Str: \"XFEATURE_MASK_FP\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x2, Str: \"XFEATURE_MASK_SSE\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x3, Str: \"XFEATURE_MASK_FPSSE\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x4, Str: \"XFEATURE_MASK_YMM\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x8, Str: \"XFEATURE_MASK_BNDREGS\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x10, Str: \"XFEATURE_MASK_BNDCSR\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x200, Str: \"XFEATURE_MASK_PKRU\"},\n")
		fmt.Fprintf(out, "\t\t},\n\t},\n")
	}
	fmt.Fprintln(out, "}")
	fmt.Fprintln(out, "var SyscallArgXlatMap = map[string]map[string]string{")
	for sc, m := range argXlat.Syscalls {
		if strings.HasSuffix(sc, "_table") { continue }
		fmt.Fprintf(out, "\t%q: {\n", sc)
		for arg, xlat := range m { fmt.Fprintf(out, "\t\t%q: %q,\n", arg, xlat) }
		fmt.Fprintln(out, "\t},")
	}
	fmt.Fprintln(out, "}")
	out.Close()
}
