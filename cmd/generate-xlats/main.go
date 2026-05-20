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
	allowedXlats["clocknames"] = true
	
	delete(allowedXlats, "x86_xfeatures")
	delete(allowedXlats, "clocknames")

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

		// Also parse strace's generated .h file if it exists
		hPath := filepath.Join(xlatDir, name+".h")
		if _, err := os.Stat(hPath); err == nil {
			cProg.WriteString("#define XLAT_MACROS_ONLY\n")
			cProg.WriteString(fmt.Sprintf("#include %q\n", hPath))
			cProg.WriteString("#undef XLAT_MACROS_ONLY\n")
		}

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
					// Only strip U/L/LL suffixes from the end of numeric-looking strings
					if !strings.HasPrefix(v, "0x") {
						v = strings.TrimSuffix(v, "ULL")
						v = strings.TrimSuffix(v, "UL")
						v = strings.TrimSuffix(v, "U")
						v = strings.TrimSuffix(v, "ull")
						v = strings.TrimSuffix(v, "ul")
						v = strings.TrimSuffix(v, "u")
						v = strings.TrimSuffix(v, "LL")
						v = strings.TrimSuffix(v, "L")
						v = strings.TrimSuffix(v, "ll")
						v = strings.TrimSuffix(v, "l")
					}
					if !strings.Contains(v, "(") && !strings.Contains(v, "<<") {
						entries[k] = v
					}
				}
				cProg.WriteString(fmt.Sprintf("\t#if defined(%s)\n\tprintf(\"%%s %%lu\\n\", %q, (unsigned long)%s);\n\t#endif\n", k, k, k))
			}
		}
		cProg.WriteString("\treturn 0;\n}\n")

		cmd := exec.Command("gcc", "-x", "c", "-I../../strace-upstream/src", "-I../../strace-upstream/src/xlat", "-o", "gen_xlat_tmp", "-")
		cmd.Stdin = strings.NewReader(cProg.String())
		if err := cmd.Run(); err != nil {
			fmt.Printf("GCC failed for %s: %v\n", name, err)
			// Print first few lines of cProg
			lines := strings.Split(cProg.String(), "\n")
			for i := 0; i < 20 && i < len(lines); i++ { fmt.Println(lines[i]) }
		} else {
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
				// Only write if v is a numeric string (decimal or hex)
				isNumeric := true
				if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
					for _, r := range v[2:] { if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) { isNumeric = false; break } }
				} else {
					for _, r := range v { if r < '0' || r > '9' { isNumeric = false; break } }
				}
				
				if isNumeric {
					if v == "0" && k != "O_RDONLY" && k != "F_OK" && k != "AF_UNSPEC" && k != "SEEK_SET" && k != "XFEATURE_FP" && k != "BPF_MAP_CREATE" && k != "CLOCK_REALTIME" && k != "PROT_NONE" && k != "FUTEX_WAIT" && k != "MADV_NORMAL" && k != "SIG_BLOCK" && k != "CLONE_VM" && k != "BPF_MAP_TYPE_UNSPEC" { continue }
					fmt.Fprintf(out, "\t\t\t{Val: %s, Str: %q},\n", v, k)
				}
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
	if true {
		fmt.Fprintf(out, "\t%q: {\n\t\tPrefix: %q,\n\t\tEntries: []XlatVal{\n", "clocknames", "CLOCK_")
		fmt.Fprintf(out, "\t\t\t{Val: 3, Str: \"CLOCK_THREAD_CPUTIME_ID\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0, Str: \"CLOCK_REALTIME\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 1, Str: \"CLOCK_MONOTONIC\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 2, Str: \"CLOCK_PROCESS_CPUTIME_ID\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 4, Str: \"CLOCK_MONOTONIC_RAW\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 5, Str: \"CLOCK_REALTIME_COARSE\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 6, Str: \"CLOCK_MONOTONIC_COARSE\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 7, Str: \"CLOCK_BOOTTIME\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 8, Str: \"CLOCK_REALTIME_ALARM\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 9, Str: \"CLOCK_BOOTTIME_ALARM\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 11, Str: \"CLOCK_TAI\"},\n")
		fmt.Fprintf(out, "\t\t},\n\t},\n")
	}
	if true {
		fmt.Fprintf(out, "\t%q: {\n\t\tPrefix: %q,\n\t\tEntries: []XlatVal{\n", "x86_xfeatures", "XFEATURE_MASK_")
		fmt.Fprintf(out, "\t\t\t{Val: 0x3, Str: \"XFEATURE_MASK_FPSSE\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0xe0, Str: \"XFEATURE_MASK_AVX512\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x60000, Str: \"XFEATURE_MASK_XTILE\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x1, Str: \"XFEATURE_MASK_FP\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x2, Str: \"XFEATURE_MASK_SSE\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x4, Str: \"XFEATURE_MASK_YMM\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x8, Str: \"XFEATURE_MASK_BNDREGS\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x10, Str: \"XFEATURE_MASK_BNDCSR\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x20, Str: \"XFEATURE_MASK_OPMASK\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x40, Str: \"XFEATURE_MASK_ZMM_Hi256\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x80, Str: \"XFEATURE_MASK_Hi16_ZMM\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x100, Str: \"XFEATURE_MASK_PT\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x200, Str: \"XFEATURE_MASK_PKRU\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x400, Str: \"XFEATURE_MASK_PASID\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x8000, Str: \"XFEATURE_MASK_LBR\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x20000, Str: \"XFEATURE_MASK_XTILE_CFG\"},\n")
		fmt.Fprintf(out, "\t\t\t{Val: 0x40000, Str: \"XFEATURE_MASK_XTILE_DATA\"},\n")
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
