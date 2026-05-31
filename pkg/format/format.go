package format

import (
	"encoding/binary"
	"fmt"
	"strings"

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
	maj := uint32((dev >> 8) & 0xfff)
	min := uint32(dev & 0xff)
	maj |= uint32((dev >> 32) & 0xfffff000)
	min |= uint32((dev >> 12) & 0xffffff00)
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
