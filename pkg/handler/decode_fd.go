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
		if ctx.Opts == nil || !ctx.Opts.ShowPathsValue() {
			return s
		}

		cwdPath := ""
		if ctx.FDStateView != nil {
			cwdPath, _ = ctx.FDStateView.Cwd(ctx.TargetPid)
			if cwdPath == "" {
				cwdPath, _ = ctx.FDStateView.Cwd(ctx.Pid)
			}
		}
		if cwdPath == "" && ctx.EventFDView != nil {
			cwdPath, _ = ctx.EventFDView.Cwd()
		}
		// IMPACT: Do not append resolved path if its length >= PATH_MAX (4096) to align with standard AT_FDCWD encoding rules.
		if cwdPath != "" && len(cwdPath) < 4096 {
			return s + "<" + cwdPath + ">"
		}
		return s
	}
	if ctx.Opts != nil && ctx.Opts.ShowPathsValue() {
		return FormatFdWithPath(ctx, int32(val))
	}
	return fmt.Sprintf("%d", int32(val))
}

func formatAtFdcwd(ctx *Context) string {
	switch xlatFormat(ctx) {
	case "raw":
		return fmt.Sprintf("%d", AtFdcwd)
	case "verbose":
		return fmt.Sprintf("%d /* AT_FDCWD */", AtFdcwd)
	}
	return "AT_FDCWD"
}

// IMPACT: FormatFdWithPath formats file descriptor with path information (-y/-yy).
// IMPACT: Strip surrounding quotes from target path returned by the FD reader
// to ensure consistent no-quote formatting inside fd paths.
func FormatFdWithPath(ctx *Context, fd int32) string {
	fdStr := fmt.Sprintf("%d", fd)
	if ctx.Opts == nil || !ctx.Opts.ShowPathsValue() {
		return fdStr
	}

	if ctx.EventFDView != nil {
		if target, ok := ctx.EventFDView.Path(fd); ok {
			return formatFDTarget(ctx, fd, target)
		}
	}
	if target, ok := lookupTrackedFDPath(ctx, fd); ok {
		return formatFDTarget(ctx, fd, target)
	}
	return fdStr
}

func formatFDTarget(ctx *Context, fd int32, target string) string {
	if ctx.Opts.ShowPathsModeValue() == 2 {
		return fmt.Sprintf("%d<%s>", fd, formatDetailedPath(ctx, target, fd))
	}
	if strings.HasPrefix(target, "socket:[") {
		target = formatSocketPath(ctx, target, fd)
	}
	return fmt.Sprintf("%d<%s>", fd, target)
}

func lookupTrackedFDPath(ctx *Context, fd int32) (string, bool) {
	if ctx == nil || ctx.FDStateView == nil {
		return "", false
	}
	for _, pid := range []int{ctx.TargetPid, ctx.Pid} {
		if target, ok := ctx.FDStateView.Path(pid, fd); ok {
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
	if observation, ok := eventFDState(ctx, fd); ok {
		if detailed := formatDevicePath(target, observation); detailed != "" {
			return detailed
		}
	}
	return target
}

func eventFDState(ctx *Context, fd int32) (FDStateObservation, bool) {
	if ctx != nil && ctx.EventFDView != nil {
		if observation, ok := ctx.EventFDView.Observation(fd); ok {
			return observation, true
		}
	}
	return ctx.FDState(fd)
}

func formatDevicePath(target string, observation FDStateObservation) string {
	const typeMask = 0170000
	const charDevice = 0020000
	const blockDevice = 0060000
	switch observation.Mode & typeMask {
	case charDevice:
		return fmt.Sprintf("%s<char %d:%d>", target, deviceMajor(observation.Rdev), deviceMinor(observation.Rdev))
	case blockDevice:
		return fmt.Sprintf("%s<block %d:%d>", target, deviceMajor(observation.Rdev), deviceMinor(observation.Rdev))
	default:
		return ""
	}
}

func deviceMajor(dev uint64) uint32 {
	return uint32((dev >> 20) & 0xfff)
}

func deviceMinor(dev uint64) uint32 {
	return uint32(dev & 0xfffff)
}

// formatSocketPath converts socket inode description using event-sourced domain information.
func formatSocketPath(ctx *Context, target string, fd int32) string {
	inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
	if ctx == nil || ctx.FDStateView == nil {
		return target
	}
	info, ok := ctx.FDStateView.Path(ctx.TargetPid, fd)
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

	if ctx.Opts != nil && ctx.Opts.ShowPathsModeValue() == 2 {
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
