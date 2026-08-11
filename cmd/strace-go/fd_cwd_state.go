package main

import (
	"fmt"
	"strings"

	"strace-go/pkg/meta"
)

func updateCwdFDMapFromView(src fdStateSource, scMeta meta.Syscall, pathText string, targetPid int, fdMap map[string]string) {
	view := src.view
	if !view.valid || view.ret != 0 {
		return
	}
	switch scMeta.Name {
	case "chdir":
		if pathText != "" && !strings.HasPrefix(pathText, "0x") && pathText != "NULL" {
			updateCwdFromPath(targetPid, pathText, fdMap)
		}
	case "fchdir":
		updateCwdFromFD(targetPid, int32(view.args[0]), fdMap)
	}
}

func updateCwdFromPath(targetPID int, pathText string, fdMap map[string]string) {
	cwdKey := fmt.Sprintf("%d:cwd", targetPID)
	base := fdMap[cwdKey]
	pathText = strings.TrimSuffix(strings.TrimPrefix(pathText, `"`), `"`)
	fdMap[cwdKey] = cleanFDStatePath(base, pathText)
}

func updateCwdFromFD(targetPID int, fd int32, fdMap map[string]string) {
	path, ok := fdMap[fdStateKey(targetPID, fd)]
	if ok {
		fdMap[fmt.Sprintf("%d:cwd", targetPID)] = path
	}
}

func cleanFDStatePath(base string, relative string) string {
	if strings.HasPrefix(relative, "/") {
		return cleanAbsoluteFDStatePath(relative)
	}
	if base == "" {
		return relative
	}
	return cleanAbsoluteFDStatePath(base + "/" + relative)
}

func cleanAbsoluteFDStatePath(path string) string {
	parts := strings.Split(path, "/")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			if len(result) > 0 {
				result = result[:len(result)-1]
			}
			continue
		}
		result = append(result, part)
	}
	return "/" + strings.Join(result, "/")
}
