package format

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"strace-go/pkg/meta"
)

// Whence formats the whence argument of lseek.
func Whence(val uint64) string {
	switch val {
	case 0: return "SEEK_SET"
	case 1: return "SEEK_CUR"
	case 2: return "SEEK_END"
	case 3: return "SEEK_DATA"
	case 4: return "SEEK_HOLE"
	default: return fmt.Sprintf("%d", val)
	}
}

// Timespec formats a struct timespec buffer into a human-readable string.
func Timespec(data []byte) string {
	if len(data) < 16 { return "{...}" }
	sec := int64(binary.LittleEndian.Uint64(data[0:8]))
	nsec := binary.LittleEndian.Uint64(data[8:16])
	return fmt.Sprintf("{tv_sec=%d, tv_nsec=%d}", sec, nsec)
}

// Timeval formats a struct timeval buffer into a human-readable string.
func Timeval(data []byte) string {
	if len(data) < 16 { return "{...}" }
	sec := int64(binary.LittleEndian.Uint64(data[0:8]))
	usec := binary.LittleEndian.Uint64(data[8:16])
	return fmt.Sprintf("{tv_sec=%d, tv_usec=%d}", sec, usec)
}

// Pollfds formats an array of struct pollfd.
func Pollfds(data []byte, nfds uint32) string {
	if len(data) < 8 { return "[]" }
	var res []string
	for i := 0; i < int(nfds) && i < 16; i++ {
		off := i * 8
		if off+8 > len(data) { break }
		fd := int32(binary.LittleEndian.Uint32(data[off : off+4]))
		events := int16(binary.LittleEndian.Uint16(data[off+4 : off+6]))
		revents := int16(binary.LittleEndian.Uint16(data[off+6 : off+8]))
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
		data_ := binary.LittleEndian.Uint64(data[off+4 : off+12])
		eventsStr := meta.DecodeFlags(uint64(events), "epollevents")
		if (data_ >> 32) == 0 {
			res = append(res, fmt.Sprintf("{events=%s, data={u32=%d, u64=%#x}}", eventsStr, uint32(data_), data_))
		} else {
			res = append(res, fmt.Sprintf("{events=%s, data=%#x}", eventsStr, data_))
		}
	}
	if count > 16 { res = append(res, "...") }
	return "[" + strings.Join(res, ", ") + "]"
}

// EpollEvent formats a single struct epoll_event (used in epoll_ctl).
func EpollEvent(data []byte) string {
	if len(data) < 12 { return "{...}" }
	events := binary.LittleEndian.Uint32(data[0:4])
	data_ := binary.LittleEndian.Uint64(data[4:12])
	eventsStr := meta.DecodeFlags(uint64(events), "epollevents")
	if (data_ >> 32) == 0 {
		return fmt.Sprintf("{events=%s, data={u32=%d, u64=%#x}}", eventsStr, uint32(data_), data_)
	}
	return fmt.Sprintf("{events=%s, data=%#x}", eventsStr, data_)
}

// IoEvents formats an array of struct io_event.
func IoEvents(data []byte, count int) string {
	if len(data) < 32 { return "[]" }
	var res []string
	for i := 0; i < count && i < 16; i++ {
		off := i * 32
		if off+32 > len(data) { break }
		data_ := binary.LittleEndian.Uint64(data[off : off+8])
		obj := binary.LittleEndian.Uint64(data[off+8 : off+16])
		res_ := int64(binary.LittleEndian.Uint64(data[off+16 : off+24]))
		res2 := int64(binary.LittleEndian.Uint64(data[off+24 : off+32]))
		res = append(res, fmt.Sprintf("{data=%#x, obj=%#x, res=%d, res2=%d}", data_, obj, res_, res2))
	}
	if count > 16 { res = append(res, "...") }
	return "[" + strings.Join(res, ", ") + "]"
}

// Stat formats a struct stat buffer into a human-readable string.
func Stat(data []byte) string {
	if len(data) < 144 { return "{...}" }
	st_dev := binary.LittleEndian.Uint64(data[0:8])
	st_ino := binary.LittleEndian.Uint64(data[8:16])
	st_nlink := binary.LittleEndian.Uint64(data[16:24])
	st_mode := binary.LittleEndian.Uint32(data[24:28])
	st_uid := binary.LittleEndian.Uint32(data[28:32])
	st_gid := binary.LittleEndian.Uint32(data[32:36])
	// data[36:40] is padding
	st_rdev := binary.LittleEndian.Uint64(data[40:48])
	st_size := int64(binary.LittleEndian.Uint64(data[48:56]))
	st_blksize := int64(binary.LittleEndian.Uint64(data[56:64]))
	st_blocks := int64(binary.LittleEndian.Uint64(data[64:72]))
	st_atime := int64(binary.LittleEndian.Uint64(data[72:80]))
	st_atime_nsec := int64(binary.LittleEndian.Uint64(data[80:88]))
	st_mtime := int64(binary.LittleEndian.Uint64(data[88:96]))
	st_mtime_nsec := int64(binary.LittleEndian.Uint64(data[96:104]))
	st_ctime := int64(binary.LittleEndian.Uint64(data[104:112]))
	st_ctime_nsec := int64(binary.LittleEndian.Uint64(data[112:120]))

	modeStr := meta.DecodeFlags(uint64(st_mode&0170000), "modetypes")
	if modeStr == fmt.Sprintf("%#x", uint64(st_mode&0170000)) {
		modeStr = fmt.Sprintf("%#o", st_mode)
	} else {
		modeStr += fmt.Sprintf("|%#03o", st_mode&07777)
	}

	res := fmt.Sprintf("{st_dev=%s, st_ino=%d, st_mode=%s, st_nlink=%d, st_uid=%d, st_gid=%d, st_blksize=%d, st_blocks=%d", Dev(st_dev), st_ino, modeStr, st_nlink, st_uid, st_gid, st_blksize, st_blocks)
	if (st_mode&0170000) != 0020000 && (st_mode&0170000) != 0060000 { res += fmt.Sprintf(", st_size=%d", st_size) } else { res += fmt.Sprintf(", st_rdev=%s", Dev(st_rdev)) }
	res += fmt.Sprintf(", st_atime=%d /* %s */, st_atime_nsec=%d, st_mtime=%d /* %s */, st_mtime_nsec=%d, st_ctime=%d /* %s */, st_ctime_nsec=%d}", st_atime, time.Unix(st_atime, 0).UTC().Format("2006-01-02T15:04:05")+"."+fmt.Sprintf("%09d", st_atime_nsec)+"+0000", st_atime_nsec, st_mtime, time.Unix(st_mtime, 0).UTC().Format("2006-01-02T15:04:05")+"."+fmt.Sprintf("%09d", st_mtime_nsec)+"+0000", st_mtime_nsec, st_ctime, time.Unix(st_ctime, 0).UTC().Format("2006-01-02T15:04:05")+"."+fmt.Sprintf("%09d", st_ctime_nsec)+"+0000", st_ctime_nsec)
	return res
}

// Timex formats a struct timex buffer into a human-readable string.
func Timex(data []byte) string {
	if len(data) < 208 { return "{...}" }
	modes := binary.LittleEndian.Uint32(data[0:4]); status := meta.DecodeFlags(uint64(binary.LittleEndian.Uint32(data[40:44])), "adjtimex_status")
	offset := int64(binary.LittleEndian.Uint64(data[8:16])); freq := int64(binary.LittleEndian.Uint64(data[16:24]))
	maxerror := int64(binary.LittleEndian.Uint64(data[24:32])); esterror := int64(binary.LittleEndian.Uint64(data[32:40]))
	constant := int64(binary.LittleEndian.Uint64(data[48:56])); precision := int64(binary.LittleEndian.Uint64(data[56:64]))
	tolerance := int64(binary.LittleEndian.Uint64(data[64:72]))
	tv_sec := int64(binary.LittleEndian.Uint64(data[72:80])); tv_usec := int64(binary.LittleEndian.Uint64(data[80:88]))
	tick := int64(binary.LittleEndian.Uint64(data[88:96]))
	ppsfreq := int64(binary.LittleEndian.Uint64(data[96:104])); jitter := int64(binary.LittleEndian.Uint64(data[104:112]))
	shift := int32(binary.LittleEndian.Uint32(data[112:116])); stabil := int64(binary.LittleEndian.Uint64(data[120:128]))
	jitcnt := int64(binary.LittleEndian.Uint64(data[128:136])); calcnt := int64(binary.LittleEndian.Uint64(data[136:144]))
	errcnt := int64(binary.LittleEndian.Uint64(data[144:152])); stbcnt := int64(binary.LittleEndian.Uint64(data[152:160]))
	tai := int32(binary.LittleEndian.Uint32(data[160:164]))

	return fmt.Sprintf("{modes=%d, offset=%d, freq=%d, maxerror=%d, esterror=%d, status=%s, constant=%d, precision=%d, tolerance=%d, time={tv_sec=%d, tv_usec=%d}, tick=%d, ppsfreq=%d, jitter=%d, shift=%d, stabil=%d, jitcnt=%d, calcnt=%d, errcnt=%d, stbcnt=%d, tai=%d}", modes, offset, freq, maxerror, esterror, status, constant, precision, tolerance, tv_sec, tv_usec, tick, ppsfreq, jitter, shift, stabil, jitcnt, calcnt, errcnt, stbcnt, tai)
}

// Termios formats a struct termios.
func Termios(data []byte) string { return "{...}" }

// Winsize formats a struct winsize.
func Winsize(data []byte) string { return "{...}" }

// Sigset formats a sigset_t bitmask into a list of signals.
func Sigset(data []byte) string {
	if len(data) < 8 { return "[]" }
	mask := binary.LittleEndian.Uint64(data[0:8])
	if mask == 0 { return "[]" }
	if mask == ^uint64(0) { return "~[]" }

	names := []string{
		"HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE",
		"KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM", "STKFLT",
		"CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU",
		"XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS",
	}

	// Determine if we should show it normally or inverted
	count := 0
	for i := 0; i < 64; i++ {
		if (mask & (1 << uint(i))) != 0 { count++ }
	}

	useInverted := count > 32
	displayMask := mask
	prefix := ""
	if useInverted {
		displayMask = ^mask
		prefix = "~"
	}

	var res []string
	for i, name := range names {
		if (displayMask & (1 << uint(i))) != 0 {
			res = append(res, name)
		}
	}
	for i := 32; i < 64; i++ {
		if (displayMask & (1 << uint(i-1))) != 0 {
			res = append(res, fmt.Sprintf("%d", i))
		}
	}

	if len(res) == 0 && prefix == "" { return "[]" }
	return prefix + "[" + strings.Join(res, " ") + "]"
}

// Dirents formats an array of dirents.
func Dirents(data []byte, count int) string { return "{...}" }

// Utimes formats an array of two struct timespec (used in utimensat).
func Utimes(data []byte) string {
	if len(data) < 32 {
		return "[{...}, {...}]"
	}
	formatTimespec := func(sec int64, nsec uint64) string {
		if nsec == 1073741823 {
			return "UTIME_NOW"
		}
		if nsec == 1073741822 {
			return "UTIME_OMIT"
		}

		timeStr := fmt.Sprintf("{tv_sec=%d, tv_nsec=%d}", sec, nsec)
		// For positive or reasonable times, append UTC timestamp comment
		if sec > 0 && sec < 253402300799 && nsec < 1000000000 {
			t := time.Unix(sec, 0).UTC()
			comment := fmt.Sprintf(" /* %s.%09d+0000 */", t.Format("2006-01-02T15:04:05"), nsec)
			return timeStr + comment
		}
		return timeStr
	}

	sec1 := int64(binary.LittleEndian.Uint64(data[0:8]))
	nsec1 := binary.LittleEndian.Uint64(data[8:16])
	sec2 := int64(binary.LittleEndian.Uint64(data[16:24]))
	nsec2 := binary.LittleEndian.Uint64(data[24:32])

	return "[" + formatTimespec(sec1, nsec1) + ", " + formatTimespec(sec2, nsec2) + "]"
}

// Sockaddr formats a sockaddr structure based on its address family.
func Sockaddr(data []byte, alen uint32, inLen uint32) string {
	if len(data) < 2 { return "{...}" }
	family := binary.LittleEndian.Uint16(data[0:2])
	switch family {
	case 1: // AF_UNIX
		// IMPACT: Safe-guard UNIX domain socket decoding using active address length (alen) to prevent reading stale buffer bytes.
		if len(data) <= 2 || alen <= 2 {
			return "{sa_family=AF_UNIX}"
		}
		pathBytes := data[2:]
		pathLen := int(alen) - 2
		if pathLen < 0 { pathLen = 0 }
		if pathLen > len(pathBytes) { pathLen = len(pathBytes) }
		pathBytes = pathBytes[:pathLen]
		
		if len(pathBytes) > 0 && pathBytes[0] == 0 {
			// Abstract socket
			return fmt.Sprintf("{sa_family=AF_UNIX, sun_path=%s}", Buffer(pathBytes, 0, len(pathBytes)))
		}
		path := strings.TrimRight(string(pathBytes), "\x00")
		return fmt.Sprintf("{sa_family=AF_UNIX, sun_path=%q}", path)
	case 2: // AF_INET
		if len(data) < 8 { return "{sa_family=AF_INET, ...}" }
		port := binary.BigEndian.Uint16(data[2:4])
		ip := data[4:8]
		return fmt.Sprintf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(%q)}", port, fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]))
	case 10: // AF_INET6
		if len(data) < 28 { return "{sa_family=AF_INET6, ...}" }
		port := binary.BigEndian.Uint16(data[2:4])
		ip := data[8:24]
		return fmt.Sprintf("{sa_family=AF_INET6, sin6_port=htons(%d), sin6_addr=inet_pty(%q)}", port, fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]))
	default:
		return fmt.Sprintf("{sa_family=%d, ...}", family)
	}
}

// BufferEscape formats a byte slice as a string, respecting a limit and escape mode.
// escapeMode: 0 = default (octal for non-ascii), 1 = hex for non-ascii (-x), 2 = hex for all (-xx)
func BufferEscape(data []byte, limit int, actualLen int, escapeMode int) string {
	if len(data) == 0 { return "\"\"" }
	
	printLimit := limit
	if printLimit <= 0 { printLimit = 32 }
	if printLimit > len(data) { printLimit = len(data) }
	
	var sb strings.Builder
	sb.WriteByte('"')
	
	for i := 0; i < printLimit; i++ {
		b := data[i]
		if escapeMode == 2 {
			sb.WriteString(fmt.Sprintf("\\x%02x", b))
			continue
		}
		
		switch b {
		case '\n': sb.WriteString("\\n")
		case '\r': sb.WriteString("\\r")
		case '\t': sb.WriteString("\\t")
		case '\v': sb.WriteString("\\v")
		case '\\': sb.WriteString("\\\\")
		case '"':  sb.WriteString("\\\"")
		default:
			if b >= 32 && b <= 126 {
				sb.WriteByte(b)
			} else {
				if escapeMode == 1 {
					sb.WriteString(fmt.Sprintf("\\x%02x", b))
				} else {
					sb.WriteString(fmt.Sprintf("\\%o", b))
				}
			}
		}
	}
	
	sb.WriteByte('"')
	if actualLen > printLimit || len(data) > printLimit { sb.WriteString("...") }
	return sb.String()
}

// Buffer formats a byte slice as a string, respecting a limit.
func Buffer(data []byte, limit int, actualLen int) string {
	return BufferEscape(data, limit, actualLen, 0)
}

// FdSet formats an fd_set bitmask into a list of file descriptors.
func FdSet(data []byte, nfds int) string {
	if len(data) == 0 { return "[]" }
	var fds []string
	for i := 0; i < nfds && i < len(data)*8; i++ {
		if (data[i/8] & (1 << (uint(i) % 8))) != 0 {
			fds = append(fds, fmt.Sprintf("%d", i))
		}
	}
	return "[" + strings.Join(fds, " ") + "]"
}

// Ioc formats a generic ioctl command number.
func Ioc(val uint64) string {
	dir := (val >> 30) & 0x3
	typ := (val >> 8) & 0xff
	nr := val & 0xff
	size := (val >> 16) & 0x3fff

	if dir == 2 && typ == 0x48 && nr == 0x12 {
		return fmt.Sprintf("HIDIOCGPHYS(%d)", size)
	}
	if dir == 2 && typ == 0x45 && nr >= 0x20 && nr <= 0x3f {
		ev := nr - 0x20
		evStr := ""
		switch ev {
		case 0: evStr = "0"
		case 1: evStr = "EV_KEY"
		case 2: evStr = "EV_REL"
		case 3: evStr = "EV_ABS"
		case 4: evStr = "EV_MSC"
		case 5: evStr = "EV_SW"
		case 6: evStr = "EV_LED"
		case 7: evStr = "EV_SND"
		case 8: evStr = "EV_REP"
		case 9: evStr = "EV_FF"
		case 10: evStr = "EV_PWR"
		case 11: evStr = "EV_FF_STATUS"
		default: evStr = fmt.Sprintf("%#x /* EV_??? */", ev)
		}
		return fmt.Sprintf("EVIOCGBIT(%s, %d)", evStr, size)
	}
	if typ == 0x5a {
		switch nr {
		case 0: return "ZFS_IOC_POOL_CREATE"
		case 0x41: return "ZFS_IOC_SEND_SPACE"
		default: return fmt.Sprintf("ZFS_IOC_%#x", nr)
		}
	}
	if dir == 2 && typ == 0x12 && nr == 0x7d && size == 256 {
		return "BLKZNAME"
	}
	if dir == 0 && typ == 0x4b && nr == 1 && size == 0 {
		return "KSTAT_IOC_CHAIN_ID"
	}

	dirStr := ""
	switch dir {
	case 0: dirStr = "_IOC_NONE"
	case 1: dirStr = "_IOC_WRITE"
	case 2: dirStr = "_IOC_READ"
	case 3: dirStr = "_IOC_READ|_IOC_WRITE"
	}
	
	if dir == 0 && typ == 0 && nr == 0 && size == 0 {
		return "0"
	}

	fh := func(v uint64) string {
		if v == 0 { return "0" }
		return fmt.Sprintf("%#x", v)
	}

	return fmt.Sprintf("_IOC(%s, %s, %s, %s)", dirStr, fh(typ), fh(nr), fh(size))
}

// Hexdump returns a hexadecimal representation of the data.
func Hexdump(data []byte) string {
	var res []string
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) { end = len(data) }
		row := data[i:end]
		var hex []string
		for _, b := range row { hex = append(hex, fmt.Sprintf("%02x", b)) }
		res = append(res, strings.Join(hex, " "))
	}
	return strings.Join(res, "\n") + "\n"
}

// Dev formats a dev_t major/minor pair in the form makedev(major, minor).
func Dev(dev uint64) string {
	dev32 := uint32(dev)
	maj := uint32((dev32 >> 8) & 0xfff)
	min := uint32(dev32 & 0xff)
	maj |= uint32((dev32 >> 32) & 0xfffff000)
	min |= uint32((dev32 >> 12) & 0xffffff00)
	resMaj := fmt.Sprintf("%#x", maj)
	if maj == 0 {
		resMaj = "0"
	}
	resMin := fmt.Sprintf("%#x", min)
	if min == 0 {
		resMin = "0"
	}
	return fmt.Sprintf("makedev(%s, %s)", resMaj, resMin)
}

// formatPerms formats the permission bits (low 12 bits) of a mode.
func formatPerms(mode uint32) string {
	var parts []string
	if mode&04000 != 0 {
		parts = append(parts, "S_ISUID")
	}
	if mode&02000 != 0 {
		parts = append(parts, "S_ISGID")
	}
	if mode&01000 != 0 {
		parts = append(parts, "S_ISVTX")
	}
	permVal := mode & 0777
	if len(parts) > 0 || permVal != 0 || mode == 0 {
		if permVal == 0 {
			parts = append(parts, "000")
		} else {
			parts = append(parts, fmt.Sprintf("%#03o", permVal))
		}
	}
	return strings.Join(parts, "|")
}

func getFileTypeStr(typeVal uint32) (string, bool) {
	switch typeVal {
	case 0140000:
		return "S_IFSOCK", true
	case 0120000:
		return "S_IFLNK", true
	case 0100000:
		return "S_IFREG", true
	case 0060000:
		return "S_IFBLK", true
	case 0040000:
		return "S_IFDIR", true
	case 0020000:
		return "S_IFCHR", true
	case 0010000:
		return "S_IFIFO", true
	default:
		return "", false
	}
}

// MknodMode formats a mode parameter for mknod/mknodat.
func MknodMode(val uint16) string {
	mode := uint32(val)
	typeVal := mode & 0170000
	if typeVal == 0 {
		return formatPerms(mode)
	}
	typeStr, ok := getFileTypeStr(typeVal)
	if !ok {
		return fmt.Sprintf("%#o", mode)
	}
	perms := formatPerms(mode & 07777)
	return typeStr + "|" + perms
}

// Sysinfo formats a struct sysinfo buffer.
func Sysinfo(data []byte) string {
	if len(data) < 112 { return "{...}" }
	uptime := binary.LittleEndian.Uint64(data[0:8])
	loads := [3]uint64{
		binary.LittleEndian.Uint64(data[8:16]),
		binary.LittleEndian.Uint64(data[16:24]),
		binary.LittleEndian.Uint64(data[24:32]),
	}
	totalram := binary.LittleEndian.Uint64(data[32:40])
	freeram := binary.LittleEndian.Uint64(data[40:48])
	sharedram := binary.LittleEndian.Uint64(data[48:56])
	bufferram := binary.LittleEndian.Uint64(data[56:64])
	totalswap := binary.LittleEndian.Uint64(data[64:72])
	freeswap := binary.LittleEndian.Uint64(data[72:80])
	procs := binary.LittleEndian.Uint16(data[80:82])
	totalhigh := binary.LittleEndian.Uint64(data[88:96])
	freehigh := binary.LittleEndian.Uint64(data[96:104])
	mem_unit := binary.LittleEndian.Uint32(data[104:108])

	return fmt.Sprintf("{uptime=%d, loads=[%d, %d, %d], totalram=%d, freeram=%d, sharedram=%d, bufferram=%d, totalswap=%d, freeswap=%d, procs=%d, totalhigh=%d, freehigh=%d, mem_unit=%d}",
		uptime, loads[0], loads[1], loads[2], totalram, freeram, sharedram, bufferram, totalswap, freeswap, procs, totalhigh, freehigh, mem_unit)
}

// Statfs formats a struct statfs buffer.
func Statfs(data []byte) string {
	if len(data) < 120 { return "{...}" }
	f_type := binary.LittleEndian.Uint64(data[0:8])
	f_bsize := binary.LittleEndian.Uint64(data[8:16])
	f_blocks := binary.LittleEndian.Uint64(data[16:24])
	f_bfree := binary.LittleEndian.Uint64(data[24:32])
	f_bavail := binary.LittleEndian.Uint64(data[32:40])
	f_files := binary.LittleEndian.Uint64(data[40:48])
	f_ffree := binary.LittleEndian.Uint64(data[48:56])
	f_fsid_val0 := binary.LittleEndian.Uint32(data[56:60])
	f_fsid_val1 := binary.LittleEndian.Uint32(data[60:64])
	f_namelen := binary.LittleEndian.Uint64(data[64:72])
	f_frsize := binary.LittleEndian.Uint64(data[72:80])
	f_flags := binary.LittleEndian.Uint64(data[80:88])

	typeStr := meta.DecodeFlags(f_type, "fsmagic")
	flagsStr := meta.DecodeFlags(f_flags, "statfs_flags")

	f_fsid_str0 := fmt.Sprintf("%#x", f_fsid_val0)
	if f_fsid_val0 == 0 {
		f_fsid_str0 = "0"
	}
	f_fsid_str1 := fmt.Sprintf("%#x", f_fsid_val1)
	if f_fsid_val1 == 0 {
		f_fsid_str1 = "0"
	}

	return fmt.Sprintf("{f_type=%s, f_bsize=%d, f_blocks=%d, f_bfree=%d, f_bavail=%d, f_files=%d, f_ffree=%d, f_fsid={val=[%s, %s]}, f_namelen=%d, f_frsize=%d, f_flags=%s}",
		typeStr, f_bsize, f_blocks, f_bfree, f_bavail, f_files, f_ffree, f_fsid_str0, f_fsid_str1, f_namelen, f_frsize, flagsStr)
}

// Flock formats a struct flock buffer.
func Flock(data []byte, showsPid bool) string {
	if len(data) < 24 { return "{...}" }
	l_type := binary.LittleEndian.Uint16(data[0:2])
	l_whence := binary.LittleEndian.Uint16(data[2:4])
	l_start := int64(binary.LittleEndian.Uint64(data[8:16]))
	l_len := int64(binary.LittleEndian.Uint64(data[16:24]))

	typeStr := ""
	switch l_type {
	case 0: typeStr = "F_RDLCK"
	case 1: typeStr = "F_WRLCK"
	case 2: typeStr = "F_UNLCK"
	default: typeStr = fmt.Sprintf("%d", l_type)
	}

	res := fmt.Sprintf("{l_type=%s, l_whence=%s, l_start=%d, l_len=%d", typeStr, Whence(uint64(l_whence)), l_start, l_len)
	if showsPid && len(data) >= 28 {
		l_pid := int32(binary.LittleEndian.Uint32(data[24:28]))
		res += fmt.Sprintf(", l_pid=%d", l_pid)
	}
	res += "}"
	return res
}

// FOwnerEx formats a struct f_owner_ex buffer.
func FOwnerEx(data []byte) string {
	if len(data) < 8 { return "{...}" }
	typ := binary.LittleEndian.Uint32(data[0:4])
	pid := int32(binary.LittleEndian.Uint32(data[4:8]))
	
	typeStr := ""
	// IMPACT: Correct enum type constants for f_owner_ex where TID=0, PID=1, PGRP=2.
	switch typ {
	case 0: typeStr = "F_OWNER_TID"
	case 1: typeStr = "F_OWNER_PID"
	case 2: typeStr = "F_OWNER_PGRP"
	default: typeStr = fmt.Sprintf("%d", typ)
	}
	return fmt.Sprintf("{type=%s, pid=%d}", typeStr, pid)
}

// Delegation formats a struct delegation buffer.
// IMPACT: Decodes struct delegation fields (d_flags, d_type, and __pad) for F_GETDELEG/F_SETDELEG.
func Delegation(data []byte) string {
	if len(data) < 8 { return "{...}" }
	d_flags := binary.LittleEndian.Uint32(data[0:4])
	d_type := binary.LittleEndian.Uint16(data[4:6])
	pad := binary.LittleEndian.Uint16(data[6:8])
	
	typeStr := ""
	switch d_type {
	case 0: typeStr = "F_RDLCK"
	case 1: typeStr = "F_WRLCK"
	case 2: typeStr = "F_UNLCK"
	default: typeStr = fmt.Sprintf("%#x /* F_??? */", d_type)
	}
	
	padStr := fmt.Sprintf("%#x", pad)
	if pad == 0 {
		padStr = "0"
	}
	
	flagsStr := fmt.Sprintf("%#x", d_flags)
	if d_flags == 0 {
		flagsStr = "0"
	}
	
	return fmt.Sprintf("{d_flags=%s, d_type=%s, __pad=%s}", flagsStr, typeStr, padStr)
}
