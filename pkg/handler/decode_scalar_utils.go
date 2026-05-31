package handler

import (
	"fmt"
	"os"
	"strings"
)

// CleanPath resolves relative and absolute paths safely.
func CleanPath(base string, rel string) string {
	if strings.HasPrefix(rel, "/") {
		return cleanAbsolute(rel)
	}
	if base == "" {
		return rel
	}
	return cleanAbsolute(base + "/" + rel)
}

func cleanAbsolute(p string) string {
	parts := strings.Split(p, "/")
	var res []string
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(res) > 0 {
				res = res[:len(res)-1]
			}
			continue
		}
		res = append(res, part)
	}
	return "/" + strings.Join(res, "/")
}

// UpdateCwd updates current working directory cache state.
func UpdateCwd(targetPid int, path string, fdMap map[string]string, eventPid int) {
	cwdKey := fmt.Sprintf("%d:cwd", targetPid)
	base := fdMap[cwdKey]
	if base == "" {
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", eventPid)); err == nil {
			base = l
		}
	}
	fdMap[cwdKey] = CleanPath(base, path)
}

// UpdateCwdByFd updates tracked cwd using target FD path descriptor.
func UpdateCwdByFd(targetPid int, fd int32, fdMap map[string]string) {
	if p, ok := fdMap[fmt.Sprintf("%d:%d", targetPid, fd)]; ok {
		fdMap[fmt.Sprintf("%d:cwd", targetPid)] = p
	}
}
