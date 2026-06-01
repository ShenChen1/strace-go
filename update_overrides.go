package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	content, _ := os.ReadFile("cmd/generate-syscalls/overrides.go")
	lines := strings.Split(string(content), "\n")
	
	newLines := []string{}
	for _, line := range lines {
		if strings.Contains(line, "var manualSyscallTypes = map[string]SyscallDef{") {
			newLines = append(newLines, line)
			newLines = append(newLines, `	"setxattr": {Name: "setxattr", Args: []string{"path", "name", "value", "size", "flags"}, ArgTypes: []string{"const char *", "const char *", "const void *", "size_t", "int"}},`)
			newLines = append(newLines, `	"lsetxattr": {Name: "lsetxattr", Args: []string{"path", "name", "value", "size", "flags"}, ArgTypes: []string{"const char *", "const char *", "const void *", "size_t", "int"}},`)
			newLines = append(newLines, `	"fsetxattr": {Name: "fsetxattr", Args: []string{"fd", "name", "value", "size", "flags"}, ArgTypes: []string{"int", "const char *", "const void *", "size_t", "int"}},`)
			newLines = append(newLines, `	"getxattr": {Name: "getxattr", Args: []string{"path", "name", "value", "size"}, ArgTypes: []string{"const char *", "const char *", "void *", "size_t"}},`)
			newLines = append(newLines, `	"lgetxattr": {Name: "lgetxattr", Args: []string{"path", "name", "value", "size"}, ArgTypes: []string{"const char *", "const char *", "void *", "size_t"}},`)
			newLines = append(newLines, `	"fgetxattr": {Name: "fgetxattr", Args: []string{"fd", "name", "value", "size"}, ArgTypes: []string{"int", "const char *", "void *", "size_t"}},`)
			newLines = append(newLines, `	"listxattr": {Name: "listxattr", Args: []string{"path", "list", "size"}, ArgTypes: []string{"const char *", "char *", "size_t"}},`)
			newLines = append(newLines, `	"llistxattr": {Name: "llistxattr", Args: []string{"path", "list", "size"}, ArgTypes: []string{"const char *", "char *", "size_t"}},`)
			newLines = append(newLines, `	"flistxattr": {Name: "flistxattr", Args: []string{"fd", "list", "size"}, ArgTypes: []string{"int", "char *", "size_t"}},`)
			newLines = append(newLines, `	"removexattr": {Name: "removexattr", Args: []string{"path", "name"}, ArgTypes: []string{"const char *", "const char *"}},`)
			newLines = append(newLines, `	"lremovexattr": {Name: "lremovexattr", Args: []string{"path", "name"}, ArgTypes: []string{"const char *", "const char *"}},`)
			newLines = append(newLines, `	"fremovexattr": {Name: "fremovexattr", Args: []string{"fd", "name"}, ArgTypes: []string{"int", "const char *"}},`)
			newLines = append(newLines, `	"get_robust_list": {Name: "get_robust_list", Args: []string{"pid", "head_ptr", "len_ptr"}, ArgTypes: []string{"int", "struct robust_list_head **", "size_t *"}},`)
			newLines = append(newLines, `	"set_robust_list": {Name: "set_robust_list", Args: []string{"head", "len"}, ArgTypes: []string{"struct robust_list_head *", "size_t"}},`)
			newLines = append(newLines, `	"getitimer": {Name: "getitimer", Args: []string{"which", "value"}, ArgTypes: []string{"int", "struct itimerval *"}},`)
			newLines = append(newLines, `	"setitimer": {Name: "setitimer", Args: []string{"which", "value", "ovalue"}, ArgTypes: []string{"int", "const struct itimerval *", "struct itimerval *"}},`)
			newLines = append(newLines, `	"getpgid": {Name: "getpgid", Args: []string{"pid"}, ArgTypes: []string{"pid_t"}},`)
			newLines = append(newLines, `	"setpgid": {Name: "setpgid", Args: []string{"pid", "pgid"}, ArgTypes: []string{"pid_t", "pid_t"}},`)
			newLines = append(newLines, `	"getpriority": {Name: "getpriority", Args: []string{"which", "who"}, ArgTypes: []string{"int", "int"}},`)
			newLines = append(newLines, `	"setpriority": {Name: "setpriority", Args: []string{"which", "who", "prio"}, ArgTypes: []string{"int", "int", "int"}},`)
			newLines = append(newLines, `	"gettimeofday": {Name: "gettimeofday", Args: []string{"tv", "tz"}, ArgTypes: []string{"struct timeval *", "struct timezone *"}},`)
			newLines = append(newLines, `	"settimeofday": {Name: "settimeofday", Args: []string{"tv", "tz"}, ArgTypes: []string{"const struct timeval *", "const struct timezone *"}},`)
			continue
		}
		newLines = append(newLines, line)
	}
	os.WriteFile("cmd/generate-syscalls/overrides.go", []byte(strings.Join(newLines, "\n")), 0644)
}
