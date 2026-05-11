// Package format provides formatting functions for syscall arguments and return values.
// All functions are pure (no side effects) and depend only on pkg/meta for flag decoding.
package format

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"strace-go/pkg/meta"
)

// Errno converts a negative return value to a human-readable errno string.
func Errno(errno int64) string {
	switch errno {
	case 1: return "EPERM (Operation not permitted)"; case 2: return "ENOENT (No such file or directory)"
	case 3: return "ESRCH (No such process)"; case 4: return "EINTR (Interrupted system call)"
	case 5: return "EIO (Input/output error)"; case 7: return "E2BIG (Argument list too long)"
	case 9: return "EBADF (Bad file descriptor)"; case 11: return "EAGAIN (Resource temporarily unavailable)"
	case 12: return "ENOMEM (Cannot allocate memory)"; case 13: return "EACCES (Permission denied)"
	case 14: return "EFAULT (Bad address)"; case 16: return "EBUSY (Device or resource busy)"
	case 17: return "EEXIST (File exists)"; case 22: return "EINVAL (Invalid argument)"
	case 32: return "EPIPE (Broken pipe)"; case 36: return "ENAMETOOLONG (File name too long)"
	case 38: return "ENOSYS (Function not implemented)"; case 95: return "EOPNOTSUPP (Operation not supported)"
	}
	return fmt.Sprintf("E%d", errno)
}

// Whence converts lseek whence value to symbolic name.
func Whence(val uint64) string {
	switch val {
	case 0: return "SEEK_SET"; case 1: return "SEEK_CUR"; case 2: return "SEEK_END"
	case 3: return "SEEK_DATA"; case 4: return "SEEK_HOLE"
	}
	return fmt.Sprintf("%d", val)
}

// Hexdump produces a hex+ASCII dump of binary data.
func Hexdump(data []byte) string {
	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		n := len(data) - i
		if n > 16 { n = 16 }
		sb.WriteString(fmt.Sprintf(" | %05x  ", i))
		for j := 0; j < 16; j++ {
			if j < n {
				fmt.Fprintf(&sb, "%02x ", data[i+j])
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" ")
		for j := 0; j < n; j++ {
			c := data[i+j]
			if c >= 32 && c <= 126 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		for j := n; j < 16; j++ {
			sb.WriteByte(' ')
		}
		sb.WriteString(" |\n")
	}
	return sb.String()
}

// Buffer formats a byte slice as a quoted string with escape sequences,
// truncating at maxLen and appending "..." if needed.
func Buffer(b []byte, maxLen int, totalSize int) string {
	if len(b) == 0 { return "\"\"" }
	var sb strings.Builder
	sb.WriteByte('"'); truncated := false
	for i, c := range b {
		if i >= maxLen { truncated = true; break }
		switch c {
		case '\t': sb.WriteString("\\t"); case '\n': sb.WriteString("\\n"); case '\v': sb.WriteString("\\v")
		case '\f': sb.WriteString("\\f"); case '\r': sb.WriteString("\\r"); case '"': sb.WriteString("\\\"")
		case '\\': sb.WriteString("\\\\")
		default:
			if c >= 32 && c <= 126 { sb.WriteByte(c) } else {
				if i+1 < len(b) && b[i+1] >= '0' && b[i+1] <= '9' { sb.WriteString(fmt.Sprintf("\\%03o", c)) } else { sb.WriteString(fmt.Sprintf("\\%o", c)) }
			}
		}
	}
	sb.WriteByte('"')
	if truncated || (totalSize > 0 && totalSize > len(b)) { sb.WriteString("...") }
	return sb.String()
}

// Stat formats a struct stat buffer into a human-readable string.
func Stat(data []byte) string {
	if len(data) < 144 { return "{...}" }
	st_dev := binary.LittleEndian.Uint64(data[0:8]); st_ino := binary.LittleEndian.Uint64(data[8:16])
	st_mode := binary.LittleEndian.Uint32(data[24:28]); st_nlink := binary.LittleEndian.Uint64(data[16:24])
	st_uid := binary.LittleEndian.Uint32(data[28:32]); st_gid := binary.LittleEndian.Uint32(data[32:36])
	st_rdev := binary.LittleEndian.Uint64(data[40:48]); st_size := int64(binary.LittleEndian.Uint64(data[48:56]))
	st_blksize := int64(binary.LittleEndian.Uint64(data[56:64])); st_blocks := int64(binary.LittleEndian.Uint64(data[64:72]))
	st_atime := int64(binary.LittleEndian.Uint64(data[72:80])); st_atime_nsec := int64(binary.LittleEndian.Uint64(data[80:88]))
	st_mtime := int64(binary.LittleEndian.Uint64(data[88:96])); st_mtime_nsec := int64(binary.LittleEndian.Uint64(data[96:104]))
	st_ctime := int64(binary.LittleEndian.Uint64(data[104:112])); st_ctime_nsec := int64(binary.LittleEndian.Uint64(data[112:120]))
	modeStr := ""
	if (st_mode & 0170000) == 0100000 { modeStr = "S_IFREG" } else if (st_mode & 0170000) == 0040000 { modeStr = "S_IFDIR" } else if (st_mode & 0170000) == 0020000 { modeStr = "S_IFCHR" } else if (st_mode & 0170000) == 0060000 { modeStr = "S_IFBLK" } else if (st_mode & 0170000) == 0010000 { modeStr = "S_IFIFO" } else if (st_mode & 0170000) == 0120000 { modeStr = "S_IFLNK" } else if (st_mode & 0170000) == 0140000 { modeStr = "S_IFSOCK" }
	if modeStr != "" { modeStr += fmt.Sprintf("|0%o", st_mode&07777) } else { modeStr = fmt.Sprintf("0%o", st_mode) }
	
	formatDev := func(d uint64) string {
		maj, min := d>>8, d&0xff
		resMaj, resMin := fmt.Sprintf("%#x", maj), fmt.Sprintf("%#x", min)
		if maj == 0 { resMaj = "0" }
		if min == 0 { resMin = "0" }
		return fmt.Sprintf("makedev(%s, %s)", resMaj, resMin)
	}

	res := fmt.Sprintf("{st_dev=%s, st_ino=%d, st_mode=%s, st_nlink=%d, st_uid=%d, st_gid=%d, st_blksize=%d, st_blocks=%d", formatDev(st_dev), st_ino, modeStr, st_nlink, st_uid, st_gid, st_blksize, st_blocks)
	if (st_mode&0170000) != 0020000 && (st_mode&0170000) != 0060000 { res += fmt.Sprintf(", st_size=%d", st_size) } else { res += fmt.Sprintf(", st_rdev=%s", formatDev(st_rdev)) }
	res += fmt.Sprintf(", st_atime=%d /* %s */, st_atime_nsec=%d, st_mtime=%d /* %s */, st_mtime_nsec=%d, st_ctime=%d /* %s */, st_ctime_nsec=%d}", st_atime, time.Unix(st_atime, 0).Format("2006-01-02T15:04:05")+"."+fmt.Sprintf("%09d", st_atime_nsec)+"+0000", st_atime_nsec, st_mtime, time.Unix(st_mtime, 0).Format("2006-01-02T15:04:05")+"."+fmt.Sprintf("%09d", st_mtime_nsec)+"+0000", st_mtime_nsec, st_ctime, time.Unix(st_ctime, 0).Format("2006-01-02T15:04:05")+"."+fmt.Sprintf("%09d", st_ctime_nsec)+"+0000", st_ctime_nsec)
	return res
}

// Sockaddr formats a sockaddr structure based on its address family.
func Sockaddr(data []byte, alen uint32, inLen uint32) string {
	if alen < 2 || len(data) < 2 { return "{...}" }
	family := binary.LittleEndian.Uint16(data[0:2])
	familyStr := meta.DecodeFlags(uint64(family), "addrfams")
	if family == 1 { // AF_UNIX
		path := ""; if alen > 2 && len(data) > 2 {
			pathLen := alen - 2; if pathLen > uint32(len(data)-2) { pathLen = uint32(len(data)-2) }
			if inLen > 0 && pathLen > inLen-2 { pathLen = inLen - 2 }
			if pathLen > 0 {
				pathBytes := data[2 : 2+pathLen]
				if idx := indexByte(pathBytes, 0); idx != -1 { pathBytes = pathBytes[:idx] }
				path = string(pathBytes)
			}
		}
		if path == "" { return fmt.Sprintf("{sa_family=%s}", familyStr) }
		return fmt.Sprintf("{sa_family=%s, sun_path=%q}", familyStr, path)
	} else if family == 2 { // AF_INET
		if len(data) < 8 { return fmt.Sprintf("{sa_family=%s, ...}", familyStr) }
		port := binary.BigEndian.Uint16(data[2:4])
		addr := net.IP(data[4:8])
		return fmt.Sprintf("{sa_family=%s, sin_port=htons(%d), sin_addr=inet_addr(%q)}", familyStr, port, addr.String())
	} else if family == 10 { // AF_INET6
		if len(data) < 28 { return fmt.Sprintf("{sa_family=%s, ...}", familyStr) }
		port := binary.BigEndian.Uint16(data[2:4])
		addr := net.IP(data[8:24])
		return fmt.Sprintf("{sa_family=%s, sin6_port=htons(%d), sin6_addr=inet_pton(%q)}", familyStr, port, addr.String())
	} else if family == 16 { // AF_NETLINK
		if len(data) < 12 { return fmt.Sprintf("{sa_family=%s, ...}", familyStr) }
		pid := binary.LittleEndian.Uint32(data[4:8])
		groups := binary.LittleEndian.Uint32(data[8:12])
		return fmt.Sprintf("{sa_family=%s, nl_pid=%d, nl_groups=%#x}", familyStr, pid, groups)
	}
	return fmt.Sprintf("{sa_family=%s, ...}", familyStr)
}

// indexByte is a helper to find a byte in a slice (avoids importing bytes).
func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c { return i }
	}
	return -1
}

// Timex formats a struct timex buffer into a human-readable string.
func Timex(data []byte) string {
	if len(data) < 208 { return "{...}" }
	modes := binary.LittleEndian.Uint32(data[0:4]); status := meta.DecodeFlags(uint64(binary.LittleEndian.Uint32(data[40:44])), "adjtimex_status")
	offset := int64(binary.LittleEndian.Uint64(data[8:16])); freq := int64(binary.LittleEndian.Uint64(data[16:24]))
	maxerror := int64(binary.LittleEndian.Uint64(data[24:32])); esterror := int64(binary.LittleEndian.Uint64(data[32:40]))
	constant := int64(binary.LittleEndian.Uint64(data[48:56])); precision := int64(binary.LittleEndian.Uint64(data[56:64]))
	tolerance := int64(binary.LittleEndian.Uint64(data[64:72])); tv_sec := int64(binary.LittleEndian.Uint64(data[72:80]))
	tv_usec := int64(binary.LittleEndian.Uint64(data[80:88])); tick := int64(binary.LittleEndian.Uint64(data[88:96]))
	ppsfreq := int64(binary.LittleEndian.Uint64(data[96:104])); jitter := int64(binary.LittleEndian.Uint64(data[104:112]))
	shift := int32(binary.LittleEndian.Uint32(data[112:116])); stabil := int64(binary.LittleEndian.Uint64(data[120:128]))
	jitcnt := int64(binary.LittleEndian.Uint64(data[128:136])); calcnt := int64(binary.LittleEndian.Uint64(data[136:144]))
	errcnt := int64(binary.LittleEndian.Uint64(data[144:152])); stbcnt := int64(binary.LittleEndian.Uint64(data[152:160]))
	tai := int32(binary.LittleEndian.Uint32(data[160:164]))
	return fmt.Sprintf("{modes=%d, offset=%d, freq=%d, maxerror=%d, esterror=%d, status=%s, constant=%d, precision=%d, tolerance=%d, time={tv_sec=%d, tv_usec=%d}, tick=%d, ppsfreq=%d, jitter=%d, shift=%d, stabil=%d, jitcnt=%d, calcnt=%d, errcnt=%d, stbcnt=%d, tai=%d}", modes, offset, freq, maxerror, esterror, status, constant, precision, tolerance, tv_sec, tv_usec, tick, ppsfreq, jitter, shift, stabil, jitcnt, calcnt, errcnt, stbcnt, tai)
}

// FdSet formats a fd_set bitmask as a list of active file descriptors.
func FdSet(n int, data []byte) string {
	if len(data) == 0 { return "[]" }
	var res []string
	for i := 0; i < n; i++ {
		byteIdx := i / 8
		bitIdx := i % 8
		if byteIdx < len(data) && (data[byteIdx] & (1 << bitIdx)) != 0 {
			res = append(res, fmt.Sprintf("%d", i))
		}
	}
	return "[" + strings.Join(res, " ") + "]"
}

// Pollfds formats an array of struct pollfd into a human-readable list.
func Pollfds(data []byte, nfds uint32) string {
	if len(data) < 8 { return "[]" }
	var res []string
	for i := uint32(0); i < nfds && i < 16; i++ {
		off := i * 8
		if int(off+8) > len(data) { break }
		fd := int32(binary.LittleEndian.Uint32(data[off : off+4]))
		events := uint16(binary.LittleEndian.Uint16(data[off+4 : off+6]))
		revents := uint16(binary.LittleEndian.Uint16(data[off+6 : off+8]))
		s := fmt.Sprintf("{fd=%d, events=%s", fd, meta.DecodeFlags(uint64(events), "pollflags"))
		if revents != 0 {
			s += fmt.Sprintf(", revents=%s", meta.DecodeFlags(uint64(revents), "pollflags"))
		}
		s += "}"
		res = append(res, s)
	}
	if nfds > 16 { res = append(res, "...") }
	return "[" + strings.Join(res, ", ") + "]"
}

// EpollEvents formats an array of struct epoll_event.
func EpollEvents(data []byte, count int) string {
	if len(data) < 12 { return "[]" }
	var res []string
	for i := 0; i < count && i < 16; i++ {
		off := i * 12
		if off+12 > len(data) { break }
		events := binary.LittleEndian.Uint32(data[off : off+4])
		u64 := binary.LittleEndian.Uint64(data[off+4 : off+12])
		res = append(res, fmt.Sprintf("{events=%s, data={u32=%d, u64=%#x}}", meta.DecodeFlags(uint64(events), "epollevents"), uint32(u64), u64))
	}
	if count > 16 { res = append(res, "...") }
	return "[" + strings.Join(res, ", ") + "]"
}

// EpollEvent formats a single struct epoll_event.
func EpollEvent(data []byte) string {
	if len(data) < 12 { return "{...}" }
	events := binary.LittleEndian.Uint32(data[0 : 4])
	u64 := binary.LittleEndian.Uint64(data[4 : 12])
	return fmt.Sprintf("{events=%s, data={u32=%d, u64=%#x}}", meta.DecodeFlags(uint64(events), "epollevents"), uint32(u64), u64)
}

// Termios formats a struct termios with basic flag fields.
func Termios(data []byte) string {
	if len(data) < 16 { return "{...}" }
	iflag := binary.LittleEndian.Uint32(data[0:4])
	oflag := binary.LittleEndian.Uint32(data[4:8])
	cflag := binary.LittleEndian.Uint32(data[8:12])
	lflag := binary.LittleEndian.Uint32(data[12:16])
	return fmt.Sprintf("{iflag=%#x, oflag=%#x, cflag=%#x, lflag=%#x, ...}", iflag, oflag, cflag, lflag)
}

// Winsize formats a struct winsize.
func Winsize(data []byte) string {
	if len(data) < 8 { return "{...}" }
	row := binary.LittleEndian.Uint16(data[0:2])
	col := binary.LittleEndian.Uint16(data[2:4])
	xpixel := binary.LittleEndian.Uint16(data[4:6])
	ypixel := binary.LittleEndian.Uint16(data[6:8])
	return fmt.Sprintf("{ws_row=%d, ws_col=%d, ws_xpixel=%d, ws_ypixel=%d}", row, col, xpixel, ypixel)
}
