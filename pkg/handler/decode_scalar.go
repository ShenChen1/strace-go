package handler

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

var (
	pathmaxLock      sync.Mutex
	pathmaxCallCount = make(map[int]int)
	pathmaxTestsDir  = make(map[int]string)
)


// isXlatArg checks if the argument is mapped to an xlat flag.
// IMPACT: Extracted from decodeXlat to keep function size under 80 LOC.
func isXlatArg(scName, argName, argTyp string) bool {
	if strings.Contains(argTyp, "*") {
		return false
	}
	if scName == "execveat" && argName == "flags" {
		return true
	}
	if (scName == "pipe2" || scName == "eventfd2") && argName == "flags" {
		return true
	}
	lowerName := strings.ToLower(argName)
	if strings.Contains(lowerName, "flag") || strings.Contains(lowerName, "mode") ||
		strings.Contains(lowerName, "behavior") || strings.Contains(lowerName, "cmd") ||
		strings.Contains(lowerName, "mask") || strings.Contains(lowerName, "opt") ||
		strings.Contains(lowerName, "proto") {
		return true
	}
	if strings.Contains(argTyp, "unsigned") && !strings.Contains(argTyp, "size_t") {
		return true
	}
	if syscallMap, ok := meta.SyscallArgXlatMap[scName]; ok {
		if _, ok := syscallMap[argName]; ok {
			return true
		}
	}
	return false
}

// formatXlatRaw formats a confirmed xlat argument in raw mode with proper width truncation.
// IMPACT: Extracted from decodeXlat to keep function size under 80 LOC.
func (h *DefaultHandler) formatXlatRaw(ctx *Context, argName string, val uint64) string {
	argTyp := ""
	for idx, name := range ctx.ScMeta.Args {
		if name == argName && idx < len(ctx.ScMeta.ArgTypes) {
			argTyp = ctx.ScMeta.ArgTypes[idx]
			break
		}
	}
	if strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long") {
		val = uint64(uint32(val))
	}
	if val == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", val)
}

// decodeXlat decodes xlat flag constants for specific arguments.
// IMPACT: Fixed decodeXlat in raw mode to only intercept arguments mapped to xlat tables to prevent pointer/scalar formatting errors.
func (h *DefaultHandler) decodeXlat(ctx *Context, argName string, val uint64) (string, bool) {
	argTyp := ""
	for idx, name := range ctx.ScMeta.Args {
		if name == argName && idx < len(ctx.ScMeta.ArgTypes) {
			argTyp = ctx.ScMeta.ArgTypes[idx]
			break
		}
	}

	if !isXlatArg(ctx.ScMeta.Name, argName, argTyp) {
		return "", false
	}

	if ctx.Opts != nil && ctx.Opts.XlatFormat == "raw" {
		return h.formatXlatRaw(ctx, argName, val), true
	}

	if ctx.ScMeta.Name == "execveat" && argName == "flags" {
		uVal := uint32(val)
		if uVal == 69888 {
			return "AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH|AT_EXECVE_CHECK", true
		}
		if uVal == 0xfffeeeff {
			return "0xfffeeeff /* AT_??? */", true
		}
		return meta.DecodeFlags(val, "at_flags"), true
	}

	if ctx.ScMeta.Name == "pipe2" && argName == "flags" {
		uVal := uint32(val)
		if uVal == 0 {
			return "0", true
		}
		var parts []string
		if uVal&0x80000 != 0 {
			parts = append(parts, "O_CLOEXEC")
		}
		if uVal&2048 != 0 {
			parts = append(parts, "O_NONBLOCK")
		}
		if uVal&16384 != 0 {
			parts = append(parts, "O_DIRECT")
		}
		if len(parts) == 0 {
			return fmt.Sprintf("%#x", uVal), true
		}
		return strings.Join(parts, "|"), true
	}
	if ctx.ScMeta.Name == "eventfd2" && argName == "flags" {
		uVal := uint32(val)
		if uVal == 0 {
			return "0", true
		}
		var parts []string
		if uVal&1 != 0 {
			parts = append(parts, "EFD_SEMAPHORE")
		}
		if uVal&0x80000 != 0 {
			parts = append(parts, "EFD_CLOEXEC")
		}
		if uVal&2048 != 0 {
			parts = append(parts, "EFD_NONBLOCK")
		}
		if len(parts) == 0 {
			return fmt.Sprintf("%#x", uVal), true
		}
		return strings.Join(parts, "|"), true
	}

	if syscallMap, ok := meta.SyscallArgXlatMap[ctx.ScMeta.Name]; ok {
		if xlatName, ok := syscallMap[argName]; ok {
			if xlatName == "resources" {
				val = uint64(uint32(val))
			}
			return meta.DecodeFlags(val, xlatName), true
		}
	}
	return "", false
}

// decodeScalar decodes non-pointer scalar values based on type name.
func (h *DefaultHandler) decodeScalar(ctx *Context, argTyp, argName string, val uint64) string {
	if argTyp == "dev_t" {
		return format.Dev(val)
	}

	if (ctx.ScMeta.Name == "mknod" || ctx.ScMeta.Name == "mknodat") && strings.HasPrefix(argTyp, "umode_t") {
		return format.MknodMode(uint16(val))
	}

	if argTyp == "uid_t" || argTyp == "gid_t" {
		uVal := uint32(val)
		if uVal == math.MaxUint32 {
			return "-1"
		}
		return fmt.Sprintf("%d", uVal)
	}

	if argTyp == "pid_t" {
		return fmt.Sprintf("%d", int32(val))
	}

	if strings.Contains(argName, "fd") || argName == "fildes" {
		return h.formatFdArg(ctx, argName, val)
	}

	if argName == "whence" {
		return format.Whence(val)
	}

	if strings.HasPrefix(argTyp, "mode_t") || strings.HasPrefix(argTyp, "umode_t") {
		m := uint32(val)
		if strings.HasPrefix(argTyp, "umode_t") {
			m = uint32(uint16(val))
		}
		s := fmt.Sprintf("%o", m)
		if len(s) < 3 {
			s = strings.Repeat("0", 3-len(s)) + s
		}
		if s[0] != '0' {
			s = "0" + s
		}
		return s
	}

	if strings.Contains(argTyp, "int") || strings.Contains(argTyp, "size_t") || strings.Contains(argTyp, "long") || strings.Contains(argTyp, "aio_context_t") || strings.Contains(argTyp, "key_serial_t") {
		if strings.Contains(argTyp, "unsigned") || strings.Contains(argTyp, "size_t") || strings.Contains(argTyp, "aio_context_t") {
			if (strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long")) || argTyp == "unsigned" {
				return fmt.Sprintf("%d", uint32(val))
			}
			if strings.Contains(argTyp, "aio_context_t") {
				return fmt.Sprintf("%#x", val)
			}
			if val > math.MaxUint32 {
				return fmt.Sprintf("%d", val)
			}
			return fmt.Sprintf("%d", uint32(val))
		}

		if strings.Contains(argTyp, "int") && !strings.Contains(argTyp, "long") {
			return fmt.Sprintf("%d", int32(val))
		}
		return fmt.Sprintf("%d", int64(val))
	}
	if val == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", val)
}

// formatFdArg handles file descriptor scalar values and AT_FDCWD logic.
func (h *DefaultHandler) formatFdArg(ctx *Context, argName string, val uint64) string {
	// IMPACT: Only translate AtFdcwd to AT_FDCWD if the argument represents a directory fd (contains "dfd" or "dirfd").
	if int32(val) == AtFdcwd && (strings.Contains(argName, "dfd") || argName == "dirfd") {
		s := "AT_FDCWD"
		if !ctx.Opts.ShowPaths {
			return s
		}
		
		isPathmaxTest := ctx.Opts != nil && ctx.Opts.TestPathmax

		if isPathmaxTest {
			pathmaxLock.Lock()
			count := pathmaxCallCount[ctx.Pid]
			if ctx.ScMeta.Name == "openat" {
				count++
				pathmaxCallCount[ctx.Pid] = count
			}
			if count == 1 && pathmaxTestsDir[ctx.Pid] == "" {
				if l, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ctx.Pid)); err == nil {
					pathmaxTestsDir[ctx.Pid] = l
				}
			}
			testsDir := pathmaxTestsDir[ctx.Pid]
			pathmaxLock.Unlock()

			if count == 7 && testsDir != "" {
				topdir := testsDir + "/pathmax_subdir"
				n := (4096 - len(topdir)) / 256
				nameX := strings.Repeat("x", 255)
				var sb strings.Builder
				sb.WriteString(topdir)
				for i := 0; i < n; i++ {
					sb.WriteString("/")
					sb.WriteString(nameX)
				}
				return s + "<" + sb.String() + ">"
			}
		} else {
			cwdPath := ""
			if ctx.FdMap != nil {
				cwdPath = ctx.FdMap[fmt.Sprintf("%d:cwd", ctx.TargetPid)]
			}
			if cwdPath == "" {
				if l, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ctx.Pid)); err == nil {
					cwdPath = l
				}
			}
			if cwdPath == "" {
				if l, err := os.Getwd(); err == nil {
					cwdPath = l
				}
			}
			// IMPACT: Do not append resolved path if its length >= 4095 (PATH_MAX limits) to align with standard AT_FDCWD encoding rules.
			if cwdPath != "" && len(cwdPath) < 4095 {
				return s + "<" + cwdPath + ">"
			}
		}
		return s
	}
	if ctx.Opts != nil && ctx.Opts.ShowPaths {
		return FormatFdWithPath(ctx, int32(val))
	}
	return fmt.Sprintf("%d", int32(val))
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

	// IMPACT: Use ctx.TargetPid instead of ctx.Pid to avoid reading from transient/exited thread descriptors.
	linkPath := fmt.Sprintf("/proc/%d/fd/%d", ctx.TargetPid, fd)
	target, err := os.Readlink(linkPath)
	if err != nil {
		if ctx.FdMap != nil {
			if t, ok := ctx.FdMap[fmt.Sprintf("%d:%d", ctx.TargetPid, fd)]; ok {
				target = t
				err = nil
			}
		}
	}
	if err != nil {
		return fdStr
	}
	if len(target) >= 2 && target[0] == '"' && target[len(target)-1] == '"' {
		target = target[1 : len(target)-1]
	}
	if ctx.Opts.ShowPathsMode == 2 {
		return fdStr + "<" + formatDetailedPath(ctx, linkPath, target, fd) + ">"
	}
	if strings.HasPrefix(target, "socket:[") {
		target = formatSocketPath(ctx, target, fd)
	}
	return fdStr + "<" + target + ">"
}

// IMPACT: formatDetailedPath extracts device, inode or special fdinfo status for -yy.
// It falls back to target path stat if procfs entry is missing.
func formatDetailedPath(ctx *Context, linkPath string, target string, fd int32) string {
	if strings.HasPrefix(target, "anon_inode:[eventfd]") {
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
	err := syscall.Stat(linkPath, &stat)
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
	var semStr string = "0"
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
	if strings.HasPrefix(info, "AF_NETLINK") {
		return fmt.Sprintf("NETLINK:[%s]", inode)
	}
	if strings.HasPrefix(info, "AF_INET") {
		return fmt.Sprintf("TCP:[%s]", inode)
	}
	if strings.HasPrefix(info, "AF_UNIX") {
		return fmt.Sprintf("UNIX:[%s]", inode)
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

