package format

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Timespec formats a struct timespec buffer into a human-readable string.
func Timespec(data []byte) string {
	if len(data) < 16 {
		return "{...}"
	}
	sec := int64(binary.LittleEndian.Uint64(data[0:8]))
	nsec := binary.LittleEndian.Uint64(data[8:16])
	return fmt.Sprintf("{tv_sec=%d, tv_nsec=%d}", sec, nsec)
}

// Timeval formats a struct timeval buffer into a human-readable string.
func Timeval(data []byte) string {
	if len(data) < 16 {
		return "{...}"
	}
	sec := int64(binary.LittleEndian.Uint64(data[0:8]))
	usec := binary.LittleEndian.Uint64(data[8:16])
	return fmt.Sprintf("{tv_sec=%d, tv_usec=%d}", sec, usec)
}

// PollfdsWithCatalog formats pollfd flags using the session catalog.
func PollfdsWithCatalog(catalog FlagDecoder, data []byte, nfds uint32) string {
	if len(data) < 8 {
		return "[]"
	}
	var res []string
	for i := 0; i < int(nfds) && i < 16; i++ {
		off := i * 8
		if off+8 > len(data) {
			break
		}
		fd := int32(binary.LittleEndian.Uint32(data[off : off+4]))
		events := int16(binary.LittleEndian.Uint16(data[off+4 : off+6]))
		revents := int16(binary.LittleEndian.Uint16(data[off+6 : off+8]))
		s := fmt.Sprintf("{fd=%d, events=%s", fd, catalog.DecodeFlags(uint64(events), "pollflags"))
		if revents != 0 {
			s += fmt.Sprintf(", revents=%s", catalog.DecodeFlags(uint64(revents), "pollflags"))
		}
		s += "}"
		res = append(res, s)
	}
	if nfds > 16 {
		res = append(res, "...")
	}
	return "[" + strings.Join(res, ", ") + "]"
}

// EpollEventsWithCatalog formats epoll events using the session catalog.
func EpollEventsWithCatalog(catalog FlagDecoder, data []byte, count int) string {
	if len(data) < 12 {
		return "[]"
	}
	var res []string
	for i := 0; i < count && i < 16; i++ {
		off := i * 12
		if off+12 > len(data) {
			break
		}
		events := binary.LittleEndian.Uint32(data[off : off+4])
		data_ := binary.LittleEndian.Uint64(data[off+4 : off+12])
		eventsStr := catalog.DecodeFlags(uint64(events), "epollevents")
		if (data_ >> 32) == 0 {
			res = append(res, fmt.Sprintf("{events=%s, data={u32=%d, u64=%#x}}", eventsStr, uint32(data_), data_))
		} else {
			res = append(res, fmt.Sprintf("{events=%s, data=%#x}", eventsStr, data_))
		}
	}
	if count > 16 {
		res = append(res, "...")
	}
	return "[" + strings.Join(res, ", ") + "]"
}

// EpollEventWithCatalog formats one epoll event using the session catalog.
func EpollEventWithCatalog(catalog FlagDecoder, data []byte) string {
	if len(data) < 12 {
		return "{...}"
	}
	events := binary.LittleEndian.Uint32(data[0:4])
	data_ := binary.LittleEndian.Uint64(data[4:12])
	eventsStr := catalog.DecodeFlags(uint64(events), "epollevents")
	if (data_ >> 32) == 0 {
		return fmt.Sprintf("{events=%s, data={u32=%d, u64=%#x}}", eventsStr, uint32(data_), data_)
	}
	return fmt.Sprintf("{events=%s, data=%#x}", eventsStr, data_)
}

// IoEvents formats an array of struct io_event.
func IoEvents(data []byte, count int) string {
	if len(data) < 32 {
		return "[]"
	}
	var res []string
	for i := 0; i < count && i < 16; i++ {
		off := i * 32
		if off+32 > len(data) {
			break
		}
		data_ := binary.LittleEndian.Uint64(data[off : off+8])
		obj := binary.LittleEndian.Uint64(data[off+8 : off+16])
		res_ := int64(binary.LittleEndian.Uint64(data[off+16 : off+24]))
		res2 := int64(binary.LittleEndian.Uint64(data[off+24 : off+32]))
		res = append(res, fmt.Sprintf("{data=%#x, obj=%#x, res=%d, res2=%d}", data_, obj, res_, res2))
	}
	if count > 16 {
		res = append(res, "...")
	}
	return "[" + strings.Join(res, ", ") + "]"
}

// StatWithCatalog formats stat mode bits using the session catalog.
func StatWithCatalog(catalog FlagDecoder, data []byte) string {
	if len(data) < 144 {
		return "{...}"
	}
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

	modeStr := catalog.DecodeFlags(uint64(st_mode&0170000), "modetypes")
	if modeStr == fmt.Sprintf("%#x", uint64(st_mode&0170000)) {
		modeStr = fmt.Sprintf("%#o", st_mode)
	} else {
		modeStr += fmt.Sprintf("|%#03o", st_mode&07777)
	}

	res := fmt.Sprintf("{st_dev=%s, st_ino=%d, st_mode=%s, st_nlink=%d, st_uid=%d, st_gid=%d, st_blksize=%d, st_blocks=%d", Dev(st_dev), st_ino, modeStr, st_nlink, st_uid, st_gid, st_blksize, st_blocks)
	if (st_mode&0170000) != 0020000 && (st_mode&0170000) != 0060000 {
		res += fmt.Sprintf(", st_size=%d", st_size)
	} else {
		res += fmt.Sprintf(", st_rdev=%s", Dev(st_rdev))
	}
	res += fmt.Sprintf(", st_atime=%d /* %s */, st_atime_nsec=%d, st_mtime=%d /* %s */, st_mtime_nsec=%d, st_ctime=%d /* %s */, st_ctime_nsec=%d}", st_atime, time.Unix(st_atime, 0).UTC().Format("2006-01-02T15:04:05")+"."+fmt.Sprintf("%09d", st_atime_nsec)+"+0000", st_atime_nsec, st_mtime, time.Unix(st_mtime, 0).UTC().Format("2006-01-02T15:04:05")+"."+fmt.Sprintf("%09d", st_mtime_nsec)+"+0000", st_mtime_nsec, st_ctime, time.Unix(st_ctime, 0).UTC().Format("2006-01-02T15:04:05")+"."+fmt.Sprintf("%09d", st_ctime_nsec)+"+0000", st_ctime_nsec)
	return res
}

// TimexWithCatalog formats timex status using the session catalog.
func TimexWithCatalog(catalog FlagDecoder, data []byte) string {
	if len(data) < 208 {
		return "{...}"
	}
	modes := binary.LittleEndian.Uint32(data[0:4])
	status := catalog.DecodeFlags(uint64(binary.LittleEndian.Uint32(data[40:44])), "adjtimex_status")
	offset := int64(binary.LittleEndian.Uint64(data[8:16]))
	freq := int64(binary.LittleEndian.Uint64(data[16:24]))
	maxerror := int64(binary.LittleEndian.Uint64(data[24:32]))
	esterror := int64(binary.LittleEndian.Uint64(data[32:40]))
	constant := int64(binary.LittleEndian.Uint64(data[48:56]))
	precision := int64(binary.LittleEndian.Uint64(data[56:64]))
	tolerance := int64(binary.LittleEndian.Uint64(data[64:72]))
	tv_sec := int64(binary.LittleEndian.Uint64(data[72:80]))
	tv_usec := int64(binary.LittleEndian.Uint64(data[80:88]))
	tick := int64(binary.LittleEndian.Uint64(data[88:96]))
	ppsfreq := int64(binary.LittleEndian.Uint64(data[96:104]))
	jitter := int64(binary.LittleEndian.Uint64(data[104:112]))
	shift := int32(binary.LittleEndian.Uint32(data[112:116]))
	stabil := int64(binary.LittleEndian.Uint64(data[120:128]))
	jitcnt := int64(binary.LittleEndian.Uint64(data[128:136]))
	calcnt := int64(binary.LittleEndian.Uint64(data[136:144]))
	errcnt := int64(binary.LittleEndian.Uint64(data[144:152]))
	stbcnt := int64(binary.LittleEndian.Uint64(data[152:160]))
	tai := int32(binary.LittleEndian.Uint32(data[160:164]))

	return fmt.Sprintf("{modes=%d, offset=%d, freq=%d, maxerror=%d, esterror=%d, status=%s, constant=%d, precision=%d, tolerance=%d, time={tv_sec=%d, tv_usec=%d}, tick=%d, ppsfreq=%d, jitter=%d, shift=%d, stabil=%d, jitcnt=%d, calcnt=%d, errcnt=%d, stbcnt=%d, tai=%d}", modes, offset, freq, maxerror, esterror, status, constant, precision, tolerance, tv_sec, tv_usec, tick, ppsfreq, jitter, shift, stabil, jitcnt, calcnt, errcnt, stbcnt, tai)
}

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
	if len(data) < 2 {
		return "{...}"
	}
	family := binary.LittleEndian.Uint16(data[0:2])
	switch family {
	case 1: // AF_UNIX
		// IMPACT: Safe-guard UNIX domain socket decoding using active address length (alen) to prevent reading stale buffer bytes.
		if len(data) <= 2 || alen <= 2 {
			return "{sa_family=AF_UNIX}"
		}
		pathBytes := data[2:]
		pathLen := int(alen) - 2
		if pathLen < 0 {
			pathLen = 0
		}
		if pathLen > len(pathBytes) {
			pathLen = len(pathBytes)
		}
		pathBytes = pathBytes[:pathLen]

		if len(pathBytes) > 0 && pathBytes[0] == 0 {
			// Abstract socket
			return fmt.Sprintf("{sa_family=AF_UNIX, sun_path=%s}", Buffer(pathBytes, 0, len(pathBytes)))
		}
		path := strings.TrimRight(string(pathBytes), "\x00")
		return fmt.Sprintf("{sa_family=AF_UNIX, sun_path=%q}", path)
	case 2: // AF_INET
		if len(data) < 8 {
			return "{sa_family=AF_INET, ...}"
		}
		port := binary.BigEndian.Uint16(data[2:4])
		ip := data[4:8]
		return fmt.Sprintf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(%q)}", port, fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]))
	case 10: // AF_INET6
		if len(data) < 28 {
			return "{sa_family=AF_INET6, ...}"
		}
		port := binary.BigEndian.Uint16(data[2:4])
		ip := data[8:24]
		return fmt.Sprintf("{sa_family=AF_INET6, sin6_port=htons(%d), sin6_addr=inet_pty(%q)}", port, fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]))
	case 16: // AF_NETLINK
		if len(data) < 12 {
			return "{sa_family=AF_NETLINK, ...}"
		}
		pid := binary.LittleEndian.Uint32(data[4:8])
		groups := binary.LittleEndian.Uint32(data[8:12])
		return fmt.Sprintf("{sa_family=AF_NETLINK, nl_pid=%d, nl_groups=%08x}", pid, groups)
	default:
		return fmt.Sprintf("{sa_family=%d, ...}", family)
	}
}

// FdSet formats an fd_set bitmask into a list of file descriptors.
func FdSet(data []byte, nfds int) string {
	if len(data) == 0 {
		return "[]"
	}
	var fds []string
	for i := 0; i < nfds && i < len(data)*8; i++ {
		if (data[i/8] & (1 << (uint(i) % 8))) != 0 {
			fds = append(fds, fmt.Sprintf("%d", i))
		}
	}
	return "[" + strings.Join(fds, " ") + "]"
}

// Sysinfo formats a struct sysinfo buffer.
func Sysinfo(data []byte) string {
	if len(data) < 112 {
		return "{...}"
	}
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

// StatfsWithCatalog formats statfs flags using the session catalog.
func StatfsWithCatalog(catalog FlagDecoder, data []byte) string {
	if len(data) < 120 {
		return "{...}"
	}
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

	typeStr := catalog.DecodeFlags(f_type, "fsmagic")
	flagsStr := catalog.DecodeFlags(f_flags, "statfs_flags")

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
