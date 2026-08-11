package handler

import (
	"fmt"
	"strings"
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
	return fdStr
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

// IMPACT: formatDetailedPath renders only metadata carried by the event-driven
// FD state. It never queries the current tracee state after the probe.
func formatDetailedPath(ctx *Context, target string, fd int32) string {
	if strings.HasPrefix(target, "socket:[") {
		return formatSocketPath(ctx, target, fd)
	}
	return target
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
			return fmt.Sprintf("TCP:[%s]", inode)
		}
		if strings.HasPrefix(domainInfo, "AF_UNIX") {
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
