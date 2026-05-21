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
		res = append(res, fmt.Sprintf("{events=%s, data={u32=%d, u64=%#x}}", meta.DecodeFlags(uint64(events), "epoll_events"), uint32(data_), data_))
	}
	if count > 16 { res = append(res, "...") }
	return "[" + strings.Join(res, ", ") + "]"
}

// EpollEvent formats a single struct epoll_event (used in epoll_ctl).
func EpollEvent(data []byte) string {
	if len(data) < 12 { return "{...}" }
	events := binary.LittleEndian.Uint32(data[0:4])
	data_ := binary.LittleEndian.Uint64(data[4:12])
	return fmt.Sprintf("{events=%s, data={u32=%d, u64=%#x}}", meta.DecodeFlags(uint64(events), "epoll_events"), uint32(data_), data_)
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

	formatDev := func(dev uint64) string {
		maj := uint32((dev >> 8) & 0xfff)
		min := uint32(dev & 0xff)
		maj |= uint32((dev >> 32) & 0xfffff000)
		min |= uint32((dev >> 12) & 0xffffff00)
		resMaj := fmt.Sprintf("%#x", maj); if maj == 0 { resMaj = "0" }
		resMin := fmt.Sprintf("%#x", min); if min == 0 { resMin = "0" }
		return fmt.Sprintf("makedev(%s, %s)", resMaj, resMin)
	}

	res := fmt.Sprintf("{st_dev=%s, st_ino=%d, st_mode=%s, st_nlink=%d, st_uid=%d, st_gid=%d, st_blksize=%d, st_blocks=%d", formatDev(st_dev), st_ino, modeStr, st_nlink, st_uid, st_gid, st_blksize, st_blocks)
	if (st_mode&0170000) != 0020000 && (st_mode&0170000) != 0060000 { res += fmt.Sprintf(", st_size=%d", st_size) } else { res += fmt.Sprintf(", st_rdev=%s", formatDev(st_rdev)) }
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

// Sigset formats a sigset_t.
func Sigset(data []byte) string { return "{...}" }

// Dirents formats an array of dirents.
func Dirents(data []byte, count int) string { return "{...}" }

// Sockaddr formats a sockaddr structure based on its address family.
func Sockaddr(data []byte, alen uint32, inLen uint32) string {
	if len(data) < 2 { return "{...}" }
	family := binary.LittleEndian.Uint16(data[0:2])
	switch family {
	case 1: // AF_UNIX
		if len(data) <= 2 {
			return "{sa_family=AF_UNIX}"
		}
		pathBytes := data[2:]
		if pathBytes[0] == 0 {
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

// Buffer formats a byte slice as a string, respecting a limit.
func Buffer(data []byte, limit int, actualLen int) string {
	if len(data) == 0 { return "\"\"" }
	
	printLimit := limit
	if printLimit <= 0 { printLimit = 32 }
	if printLimit > len(data) { printLimit = len(data) }
	
	var sb strings.Builder
	sb.WriteByte('"')
	
	for i := 0; i < printLimit; i++ {
		b := data[i]
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
				sb.WriteString(fmt.Sprintf("\\%o", b))
			}
		}
	}
	
	sb.WriteByte('"')
	if actualLen > printLimit || len(data) > printLimit { sb.WriteString("...") }
	return sb.String()
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
