package handler

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

func (r *Runtime) FDPath(pid int, fd int32) (string, bool) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
	return path, err == nil
}

func (r *Runtime) CWDPath(pid int) (string, bool) {
	path, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	return path, err == nil
}

func (r *Runtime) FDStat(pid int, fd int32) (PathStat, bool) {
	return r.PathStat(fmt.Sprintf("/proc/%d/fd/%d", pid, fd))
}

func (r *Runtime) FDOffset(pid int, fd int32) (int64, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", pid, fd))
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "pos:") {
			continue
		}
		offset, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "pos:")), 10, 64)
		if err == nil {
			return offset, true
		}
	}
	return 0, false
}

func (r *Runtime) PathStat(path string) (PathStat, bool) {
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return PathStat{}, false
	}
	return PathStat{Mode: uint64(stat.Mode), Inode: stat.Ino, Rdev: uint64(stat.Rdev)}, true
}
