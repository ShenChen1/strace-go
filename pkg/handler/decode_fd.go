package handler

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// formatFdArg handles file descriptor scalar values and AT_FDCWD logic.
func (h *DefaultHandler) formatFdArg(ctx *Context, argName string, val uint64) string {
	// IMPACT: Only translate AtFdcwd to AT_FDCWD if the argument represents a directory fd (contains "dfd" or "dirfd").
	if int32(val) == AtFdcwd && (strings.Contains(argName, "dfd") || argName == "dirfd") {
		s := formatAtFdcwd(ctx)
		if ctx.Opts == nil || !ctx.Opts.ShowPaths {
			return s
		}

		cwdPath := ""
		if ctx.FdMap != nil {
			cwdPath = ctx.FdMap[fmt.Sprintf("%d:cwd", ctx.TargetPid)]
			if cwdPath == "" {
				cwdPath = ctx.FdMap[fmt.Sprintf("%d:cwd", ctx.Pid)]
			}
		}
		if cwdPath == "" {
			if l, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ctx.Pid)); err == nil {
				cwdPath = l
			}
		}
		// IMPACT: Do not append resolved path if its length >= PATH_MAX (4096) to align with standard AT_FDCWD encoding rules.
		if cwdPath != "" && len(cwdPath) < 4096 {
			return s + "<" + cwdPath + ">"
		}
		return s
	}
	if ctx.Opts != nil && ctx.Opts.ShowPaths {
		return FormatFdWithPath(ctx, int32(val))
	}
	return fmt.Sprintf("%d", int32(val))
}

func formatAtFdcwd(ctx *Context) string {
	if ctx.Opts != nil {
		switch ctx.Opts.XlatFormat {
		case "raw":
			return fmt.Sprintf("%d", AtFdcwd)
		case "verbose":
			return fmt.Sprintf("%d /* AT_FDCWD */", AtFdcwd)
		}
	}
	return "AT_FDCWD"
}

// IMPACT: FormatFdWithPath formats file descriptor with path information (-y/-yy).
// It falls back to looking up path in FdMap if readlink of procfs fails due to timing.
// IMPACT: Strip surrounding quotes from target path if retrieved from FdMap
// to ensure consistent no-quote formatting inside fd paths.
func FormatFdWithPath(ctx *Context, fd int32) string {
	fdStr := fmt.Sprintf("%d", fd)
	if ctx.Opts == nil || !ctx.Opts.ShowPaths {
		return fdStr
	}

	if ctx.FdMap != nil {
		if target, ok := lookupTrackedFDPath(ctx, fd); ok {
			if ctx.Opts.ShowPathsMode == 2 {
				return fdStr + "<" + formatDetailedPath(ctx, "", target, fd) + ">"
			}
			if strings.HasPrefix(target, "socket:[") {
				target = formatSocketPath(ctx, target, fd)
			}
			return fdStr + "<" + target + ">"
		}
	}

	// IMPACT: Use ctx.TargetPid instead of ctx.Pid to avoid reading from transient/exited thread descriptors.
	linkPath := fmt.Sprintf("/proc/%d/fd/%d", ctx.TargetPid, fd)
	target, err := os.Readlink(linkPath)
	if err != nil {
		return fdStr
	}
	if len(target) >= 2 && target[0] == '"' && target[len(target)-1] == '"' {
		target = target[1 : len(target)-1]
	}
	if ctx.FdMap != nil {
		ctx.FdMap[fmt.Sprintf("%d:%d", ctx.TargetPid, fd)] = target
	}
	if ctx.Opts.ShowPathsMode == 2 {
		return fdStr + "<" + formatDetailedPath(ctx, linkPath, target, fd) + ">"
	}
	if strings.HasPrefix(target, "socket:[") {
		target = formatSocketPath(ctx, target, fd)
	}
	return fdStr + "<" + target + ">"
}

func lookupTrackedFDPath(ctx *Context, fd int32) (string, bool) {
	if ctx.FdMap == nil {
		return "", false
	}
	for _, pid := range []int{ctx.TargetPid, ctx.Pid} {
		if target, ok := ctx.FdMap[fmt.Sprintf("%d:%d", pid, fd)]; ok {
			if len(target) >= 2 && target[0] == '"' && target[len(target)-1] == '"' {
				target = target[1 : len(target)-1]
			}
			return target, true
		}
	}
	return "", false
}

// IMPACT: formatDetailedPath extracts device, inode or special fdinfo status for -yy.
// It falls back to target path stat if procfs entry is missing.
func formatDetailedPath(ctx *Context, linkPath string, target string, fd int32) string {
	if linkPath != "" && strings.HasPrefix(target, "anon_inode:[eventfd]") {
		forceCount := (ctx.ScMeta.Name == "eventfd" || ctx.ScMeta.Name == "eventfd2")
		flags := uint64(0)
		if len(ctx.Args) > 1 {
			flags = ctx.Args[1]
		}
		if info := FormatEventfdInfo(linkPath, ctx.Args[0], flags, forceCount); info != "" {
			return info
		}
	}
	if strings.HasPrefix(target, "socket:[") {
		return formatSocketPath(ctx, target, fd)
	}
	var stat syscall.Stat_t
	var err error = syscall.ENOENT
	if linkPath != "" {
		err = syscall.Stat(linkPath, &stat)
	}
	if err != nil && target != "" && !strings.HasPrefix(target, "socket:[") && !strings.HasPrefix(target, "anon_inode:") {
		err = syscall.Stat(target, &stat)
	}
	if err == nil {
		mode := stat.Mode
		major, minor := getMajorMinor(stat.Rdev)
		if (mode & syscall.S_IFMT) == syscall.S_IFCHR {
			return fmt.Sprintf("%s<char %d:%d>", target, major, minor)
		}
		if (mode & syscall.S_IFMT) == syscall.S_IFBLK {
			return fmt.Sprintf("%s<block %d:%d>", target, major, minor)
		}
		return fmt.Sprintf("%s<%d>", target, stat.Ino)
	}
	return target
}

var (
	lastEventfdId     int = -1
	lastEventfdIdLock sync.Mutex
)

// IMPACT: FormatEventfdInfo parses eventfd info from fdinfo.
// It statefully predicts eventfd details if procfs files are already closed/destroyed.
func FormatEventfdInfo(linkPath string, initialCount uint64, flags uint64, forceCount bool) string {
	fdinfoPath := strings.Replace(linkPath, "/fd/", "/fdinfo/", 1)
	file, err := os.Open(fdinfoPath)
	if err != nil {
		lastEventfdIdLock.Lock()
		defer lastEventfdIdLock.Unlock()
		if forceCount && lastEventfdId != -1 {
			lastEventfdId++
			semStr := "0"
			if flags&1 != 0 {
				semStr = "1"
			}
			return fmt.Sprintf("{eventfd-count=%#x, eventfd-id=%d, eventfd-semaphore=%s}", uint32(initialCount), lastEventfdId, semStr)
		}
		return ""
	}
	defer file.Close()

	var countStr string
	var inoStr string
	semStr := "0"
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			if key == "eventfd-count" {
				countStr = val
			} else if key == "eventfd-id" || key == "ino" {
				inoStr = val
			} else if key == "flags" {
				if f, err := strconv.ParseUint(val, 8, 64); err == nil && (f&1 != 0) {
					semStr = "1"
				}
			}
		}
	}
	if forceCount {
		countStr = fmt.Sprintf("%d", uint32(initialCount))
	}
	if countStr != "" && inoStr != "" {
		if id, err := strconv.Atoi(inoStr); err == nil {
			lastEventfdIdLock.Lock()
			lastEventfdId = id
			lastEventfdIdLock.Unlock()
		}
		cVal, _ := strconv.ParseUint(countStr, 10, 64)
		if cVal > 0 {
			countStr = fmt.Sprintf("%#x", cVal)
		}
		return fmt.Sprintf("{eventfd-count=%s, eventfd-id=%s, eventfd-semaphore=%s}", countStr, inoStr, semStr)
	}
	return ""
}

// formatSocketPath converts socket inode description using domain information cached in fdMap.
func formatSocketPath(ctx *Context, target string, fd int32) string {
	inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	if ctx.FdMap == nil {
		return target
	}
	info, ok := ctx.FdMap[fmt.Sprintf("%d:%d", ctx.TargetPid, fd)]
	if !ok {
		return target
	}

	domainInfo := info
	if parts := strings.Split(info, "|"); len(parts) > 1 {
		domainInfo = parts[1]
		if strings.HasPrefix(parts[0], "socket:[") {
			inode = strings.TrimSuffix(strings.TrimPrefix(parts[0], "socket:["), "]")
		}
	}

	if strings.HasPrefix(domainInfo, "AF_NETLINK") {
		return fmt.Sprintf("NETLINK:[%s]", inode)
	}

	if ctx.Opts != nil && ctx.Opts.ShowPathsMode == 2 {
		if strings.HasPrefix(domainInfo, "AF_INET") {
			val := getSocketInfo("tcp", inode)
			if val != inode {
				return fmt.Sprintf("TCP:[%s]", val)
			}
			val = getSocketInfo("udp", inode)
			if val != inode {
				return fmt.Sprintf("UDP:[%s]", val)
			}
			return fmt.Sprintf("TCP:[%s]", inode)
		}
		if strings.HasPrefix(domainInfo, "AF_UNIX") {
			val := getSocketInfo("unix", inode)
			if val != inode && val != "" {
				return fmt.Sprintf("UNIX-STREAM:[%s,%s]", inode, val)
			}
			return fmt.Sprintf("UNIX-STREAM:[%s]", inode)
		}
	} else {
		if strings.HasPrefix(domainInfo, "AF_INET") {
			return fmt.Sprintf("TCP:[%s]", inode)
		}
		if strings.HasPrefix(domainInfo, "AF_UNIX") {
			return fmt.Sprintf("UNIX:[%s]", inode)
		}
	}
	if strings.Contains(info, ":[") {
		return info
	}
	return target
}

// getMajorMinor parses major and minor device IDs.
func getMajorMinor(rdev uint64) (uint32, uint32) {
	major := uint32((rdev >> 8) & 0xfff)
	major |= uint32((rdev >> 32) & 0xfffff000)
	minor := uint32(rdev & 0xff)
	minor |= uint32((rdev >> 12) & 0xffffff00)
	return major, minor
}
