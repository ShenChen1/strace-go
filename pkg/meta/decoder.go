package meta

import (
	"fmt"
	"strings"
)

type Syscall struct {
	Name     string
	Args     []string
	ArgTypes []string
}

var ErrnoTable = map[int]string{
	1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO", 6: "ENXIO", 7: "E2BIG", 8: "ENOEXEC", 9: "EBADF", 10: "ECHILD",
	11: "EAGAIN", 12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 15: "ENOTBLK", 16: "EBUSY", 17: "EEXIST", 18: "EXDEV", 19: "ENODEV", 20: "ENOTDIR",
	21: "EISDIR", 22: "EINVAL", 23: "ENFILE", 24: "EMFILE", 25: "ENOTTY", 26: "ETXTBSY", 27: "EFBIG", 28: "ENOSPC", 29: "ESPIPE", 30: "EROFS",
	31: "EMLINK", 32: "EPIPE", 33: "EDOM", 34: "ERANGE", 35: "EDEADLK", 36: "ENAMETOOLONG", 37: "ENOLCK", 38: "ENOSYS", 39: "ENOTEMPTY", 40: "ELOOP",
	42: "ENOMSG", 43: "EIDRM", 44: "ECHRNG", 45: "EL2NSYNC", 46: "EL3HLT", 47: "EL3RST", 48: "ELNRNG", 49: "EUNATCH", 50: "ENOCSI",
	51: "EL2HLT", 52: "EBADE", 53: "EBADR", 54: "EXFULL", 55: "ENOANO", 56: "EBADRQC", 57: "EBADSLT", 59: "EBFONT", 60: "ENOSTR",
	61: "ENODATA", 62: "ETIME", 63: "ENOSR", 64: "ENONET", 65: "ENOPKG", 66: "EREMOTE", 67: "ENOLINK", 68: "EADV", 69: "ESRMNT", 70: "ECOMM",
	71: "EPROTO", 72: "EMULTIHOP", 73: "EDOTDOT", 74: "EBADMSG", 75: "EOVERFLOW", 76: "ENOTUNIQ", 77: "EBADFD", 78: "EREMCHG", 79: "ELIBACC", 80: "ELIBBAD",
	81: "ELIBSCN", 82: "ELIBMAX", 83: "ELIBEXEC", 84: "EILSEQ", 85: "ERESTART", 86: "ESTRPIPE", 87: "EUSERS", 88: "ENOTSOCK", 89: "EDESTADDRREQ", 90: "EMSGSIZE",
	91: "EPROTOTYPE", 92: "ENOPROTOOPT", 93: "EPROTONOSUPPORT", 94: "ESOCKTNOSUPPORT", 95: "EOPNOTSUPP", 96: "EPFNOSUPPORT", 97: "EAFNOSUPPORT", 98: "EADDRINUSE", 99: "EADDRNOTAVAIL", 100: "ENETDOWN",
	101: "ENETUNREACH", 102: "ENETRESET", 103: "ECONNABORTED", 104: "ECONNRESET", 105: "ENOBUFS", 106: "EISCONN", 107: "ENOTCONN", 108: "ESHUTDOWN", 109: "ETOOMANYREFS", 110: "ETIMEDOUT",
	111: "ECONNREFUSED", 112: "EHOSTDOWN", 113: "EHOSTUNREACH", 114: "EALREADY", 115: "EINPROGRESS", 116: "ESTALE", 117: "EUCLEAN", 118: "ENOTNAM", 119: "ENAVAIL", 120: "EISNAM",
	121: "EREMOTEIO", 122: "EDQUOT", 123: "ENOMEDIUM", 124: "EMEDIUMTYPE", 125: "ECANCELED", 126: "ENOKEY", 127: "EKEYEXPIRED", 128: "EKEYREVOKED", 129: "EKEYREJECTED", 130: "EOWNERDEAD",
	131: "ENOTRECOVERABLE", 132: "ERFKILL", 133: "EHWPOISON",
}

// decodeEnum formats enum xlat names.
func decodeEnum(val uint64, xlatName string, table XlatTable) (string, bool) {
	for _, entry := range table.Entries {
		if entry.Val == val || (xlatName == "key_spec" && int32(entry.Val) == int32(val)) {
			if xlatName == "x86_xfeature_bits" {
				formatVal := fmt.Sprintf("%#x", val)
				if val == 0 { formatVal = "0" }
				return fmt.Sprintf("%s /* %s */", formatVal, entry.Str), true
			}
			return entry.Str, true
		}
	}
	if (xlatName == "signalnames" || xlatName == "key_spec" || val < 100) && xlatName != "resources" {
		return fmt.Sprintf("%d", int32(val)), true
	}
	formatVal := fmt.Sprintf("%#x", val)
	if xlatName == "x86_xfeature_bits" && val < 10 { formatVal = fmt.Sprintf("%d", val) }
	if table.Prefix != "" {
		return fmt.Sprintf("%s /* %s??? */", formatVal, table.Prefix), true
	}
	return fmt.Sprintf("%s /* ??? */", formatVal), true
}

// decodeBitFlags formats bitmask xlat flags.
func decodeBitFlags(val uint64, xlatName string, table XlatTable) string {
	var res []string
	handled := uint64(0)

	if strings.Contains(xlatName, "open_mode_flags") || xlatName == "open_access_modes" {
		accMode := val & 3
		switch accMode {
		case 0: res = append(res, "O_RDONLY")
		case 1: res = append(res, "O_WRONLY")
		case 2: res = append(res, "O_RDWR")
		case 3: res = append(res, "O_ACCMODE")
		}
		handled |= accMode
	}

	for _, entry := range table.Entries {
		if entry.Val == 0 { continue }
		if (val & entry.Val) == entry.Val {
			if (handled & entry.Val) != entry.Val {
				res = append(res, entry.Str)
				handled |= entry.Val
			}
		}
	}

	if len(res) == 0 {
		if val == 0 {
			for _, entry := range table.Entries {
				if entry.Val == 0 { return entry.Str }
			}
			return "0"
		}
		if xlatName == "key_spec" {
			return fmt.Sprintf("%d", int32(val))
		}
		formatVal := fmt.Sprintf("%#x", val)
		if table.Prefix != "" {
			return fmt.Sprintf("%s /* %s??? */", formatVal, table.Prefix)
		}
		return fmt.Sprintf("%s /* ??? */", formatVal)
	}

	if handled != val && val != 0 {
		remaining := val & ^handled
		if remaining != 0 {
			res = append(res, fmt.Sprintf("%#x", remaining))
		}
	}
	return strings.Join(res, "|")
}

// DecodeFlags translates numeric flag values into human-readable strings.
// Impact: Core formatting helper for xlat flags. Used across default and specialized handlers.
func DecodeFlags(val uint64, xlatName string) string {
	table, ok := XlatTables[xlatName]
	if !ok { return fmt.Sprintf("%#x", val) }

	if xlatName != "clone3_flags" {
		val = uint64(uint32(val))
	}

	isEnum := (strings.HasSuffix(xlatName, "vals") || strings.HasSuffix(xlatName, "options") || xlatName == "socktypes" || xlatName == "bpf_commands" || xlatName == "archvals" || xlatName == "addrfams" || xlatName == "open_access_modes" || xlatName == "whence" || xlatName == "x86_xfeature_bits" || xlatName == "epollctls" || xlatName == "term_cmds_overlapping" || xlatName == "key_spec" || xlatName == "bpf_map_types" || xlatName == "signalnames" || xlatName == "clocknames" || xlatName == "bpf_prog_types" || xlatName == "bpf_attach_type" || xlatName == "futexops" || xlatName == "ioctl_cmds" || xlatName == "resources") && xlatName != "clone3_flags"

	if isEnum {
		if s, ok := decodeEnum(val, xlatName, table); ok {
			return s
		}
	} else {
		return decodeBitFlags(val, xlatName, table)
	}
	return fmt.Sprintf("%#x", val)
}
