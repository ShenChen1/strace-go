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
	xlatDir := "../../strace-upstream/src/xlat"
	data, err := os.ReadFile("arg_xlat_map.yaml")
	if err != nil {
		data, _ = os.ReadFile("../generate-xlats/arg_xlat_map.yaml")
	}
	var argXlat ArgXlatMap
	yaml.Unmarshal(data, &argXlat)

	out, _ := os.Create("../../pkg/meta/xlat_auto.go")
	fmt.Fprintln(out, "package meta")
	fmt.Fprintln(out, "type XlatVal struct { Val uint64; Str string }")
	fmt.Fprintln(out, "type XlatTable struct { Prefix string; Entries []XlatVal }")
	fmt.Fprintln(out, "var XlatTables = map[string]XlatTable{")

	allowedXlats := make(map[string]bool)
	for _, m := range argXlat.Syscalls {
		for _, xlat := range m { allowedXlats[xlat] = true }
	}
	// Manual additions
	allowedXlats["open_access_modes"] = true
	allowedXlats["addrfams"] = true
	allowedXlats["whence"] = true
	allowedXlats["adjtimex_status"] = true
	allowedXlats["x86_xfeature_bits"] = true
	allowedXlats["bpf_commands"] = true
	allowedXlats["bpf_map_types"] = true
	allowedXlats["bpf_map_flags"] = true

	files, _ := os.ReadDir(xlatDir)
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".in") { continue }
		name := strings.TrimSuffix(f.Name(), ".in")
		if !allowedXlats[name] { continue }

		content, _ := os.ReadFile(filepath.Join(xlatDir, f.Name()))
		prefix := ""
		keys := []string{}
		entries := make(map[string]string)
		
		cProg := strings.Builder{}
		cProg.WriteString("#define _GNU_SOURCE\n#include <stdio.h>\n#include <fcntl.h>\n#include <sys/types.h>\n#include <sys/socket.h>\n#include <sys/un.h>\n#include <linux/prctl.h>\n#include <asm/prctl.h>\n#include <linux/stat.h>\n#include <linux/fs.h>\n#include <linux/timex.h>\n#include <poll.h>\n#include <sys/epoll.h>\n#include <linux/bpf.h>\n#include <time.h>\n#include <asm/termios.h>\n#include <sys/mman.h>\n#include <sched.h>\n#include <linux/futex.h>\n#include <sys/wait.h>\n#include <sys/mount.h>\n#include <linux/keyctl.h>\n")
		cProg.WriteString("#ifndef ARCH_GET_CPUID\n#define ARCH_GET_CPUID 0x1011\n#endif\n#ifndef ARCH_SET_CPUID\n#define ARCH_SET_CPUID 0x1012\n#endif\n")
		cProg.WriteString("int main() {\n")

		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#Prefix ") { prefix = strings.TrimSpace(strings.TrimPrefix(line, "#Prefix ")) }
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "/") { continue }
			parts := strings.Fields(line)
			if len(parts) >= 1 { 
				k := parts[0]
				keys = append(keys, k)
				if len(parts) >= 2 {
					v := parts[1]
					if !strings.Contains(v, "(") && !strings.Contains(v, "<<") {
						v = strings.TrimSuffix(v, "ULL")
						v = strings.TrimSuffix(v, "UL")
						v = strings.TrimSuffix(v, "U")
						v = strings.TrimSuffix(v, "ull")
						v = strings.TrimSuffix(v, "ul")
						v = strings.TrimSuffix(v, "u")
						entries[k] = v
					}
				}
				cProg.WriteString(fmt.Sprintf("\t#if defined(%s)\n\tprintf(\"%%s %%lu\\n\", %q, (unsigned long)%s);\n\t#endif\n", k, k, k))
			}
		}
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
					entries[str] = v
				}
			}
			os.Remove("gen_xlat_tmp")
		}

		fmt.Fprintf(out, "\t%q: {\n\t\tPrefix: %q,\n\t\tEntries: []XlatVal{\n", name, prefix)
		for _, k := range keys {
			if v, ok := entries[k]; ok {
				if v == "0" && k != "O_RDONLY" && k != "F_OK" && k != "AF_UNSPEC" && k != "SEEK_SET" && k != "XFEATURE_FP" && k != "BPF_MAP_CREATE" && k != "CLOCK_REALTIME" && k != "PROT_NONE" && k != "FUTEX_WAIT" && k != "MADV_NORMAL" && k != "SIG_BLOCK" && k != "CLONE_VM" && k != "BPF_MAP_TYPE_UNSPEC" { continue }
				fmt.Fprintf(out, "\t\t\t{Val: %s, Str: %q},\n", v, k)
			}
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
