package handler

import (
	"fmt"
	"strings"
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
			if ctx.FDMetadata != nil {
				if path, ok := ctx.FDMetadata.CWDPath(ctx.Pid); ok {
					cwdPath = path
				}
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
				return fdStr + "<" + formatDetailedPath(ctx, target, fd) + ">"
			}
			if strings.HasPrefix(target, "socket:[") {
				target = formatSocketPath(ctx, target, fd)
			}
			return fdStr + "<" + target + ">"
		}
	}

	// IMPACT: Use ctx.TargetPid instead of ctx.Pid to avoid reading from transient/exited thread descriptors.
	if ctx.FDMetadata == nil {
		return fdStr
	}
	target, ok := ctx.FDMetadata.FDPath(ctx.TargetPid, fd)
	if !ok {
		return fdStr
	}
	if len(target) >= 2 && target[0] == '"' && target[len(target)-1] == '"' {
		target = target[1 : len(target)-1]
	}
	if ctx.FdMap != nil {
		ctx.FdMap[fmt.Sprintf("%d:%d", ctx.TargetPid, fd)] = target
	}
	if ctx.Opts.ShowPathsMode == 2 {
		return fdStr + "<" + formatDetailedPath(ctx, target, fd) + ">"
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
func formatDetailedPath(ctx *Context, target string, fd int32) string {
	if strings.HasPrefix(target, "anon_inode:[eventfd]") {
		forceCount := (ctx.ScMeta.Name == "eventfd" || ctx.ScMeta.Name == "eventfd2")
		flags := uint64(0)
		if len(ctx.Args) > 1 {
			flags = ctx.Args[1]
		}
		if info := eventfdInfo(ctx, fd, ctx.Args[0], flags, forceCount); info != "" {
			return info
		}
	}
	if strings.HasPrefix(target, "socket:[") {
		return formatSocketPath(ctx, target, fd)
	}
	if ctx.FDMetadata != nil {
		stat, ok := ctx.FDMetadata.FDStat(ctx.TargetPid, fd)
		if !ok && target != "" && !strings.HasPrefix(target, "socket:[") && !strings.HasPrefix(target, "anon_inode:") {
			stat, ok = ctx.FDMetadata.PathStat(target)
		}
		if ok {
			mode := stat.Mode
			major, minor := getMajorMinor(stat.Rdev)
			if (mode & syscall.S_IFMT) == syscall.S_IFCHR {
				return fmt.Sprintf("%s<char %d:%d>", target, major, minor)
			}
			if (mode & syscall.S_IFMT) == syscall.S_IFBLK {
				return fmt.Sprintf("%s<block %d:%d>", target, major, minor)
			}
			return fmt.Sprintf("%s<%d>", target, stat.Inode)
		}
	}
	return target
}

func eventfdInfo(ctx *Context, fd int32, initialCount uint64, flags uint64, forceCount bool) string {
	if ctx == nil || ctx.FDMetadata == nil {
		return ""
	}
	return ctx.FDMetadata.EventfdInfo(ctx.TargetPid, fd, initialCount, flags, forceCount)
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
			val := socketInfo(ctx, "tcp", inode)
			if val != inode {
				return fmt.Sprintf("TCP:[%s]", val)
			}
			val = socketInfo(ctx, "udp", inode)
			if val != inode {
				return fmt.Sprintf("UDP:[%s]", val)
			}
			return fmt.Sprintf("TCP:[%s]", inode)
		}
		if strings.HasPrefix(domainInfo, "AF_UNIX") {
			val := socketInfo(ctx, "unix", inode)
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

func socketInfo(ctx *Context, proto string, inode string) string {
	if ctx == nil || ctx.Runtime == nil {
		return inode
	}
	return ctx.Runtime.SocketInfo(proto, inode)
}

// getMajorMinor parses major and minor device IDs.
func getMajorMinor(rdev uint64) (uint32, uint32) {
	major := uint32((rdev >> 8) & 0xfff)
	major |= uint32((rdev >> 32) & 0xfffff000)
	minor := uint32(rdev & 0xff)
	minor |= uint32((rdev >> 12) & 0xffffff00)
	return major, minor
}
