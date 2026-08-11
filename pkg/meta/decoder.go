package meta

import (
	"fmt"
	"strings"
)

type Syscall struct {
	Name     string
	Args     []string
	ArgTypes []string
	Flags    string
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
// Impact: Formats enum values. BPF enums (prefix "bpf_") are excluded from decimal fallback to preserve raw hex formatting.
// Collecting overlapping entries and joining them with " or " resolves macro conflicts in tests.
func decodeEnum(val uint64, xlatName string, table XlatTable) (string, bool) {
	var matches []string
	for _, entry := range table.Entries {
		if entry.Val == val || (xlatName == "key_spec" && int32(entry.Val) == int32(val)) {
			if xlatName == "x86_xfeature_bits" {
				formatVal := fmt.Sprintf("%#x", val)
				if val == 0 {
					formatVal = "0"
				}
				return fmt.Sprintf("%s /* %s */", formatVal, entry.Str), true
			}
			// Avoid duplicate string entries in matches
			duplicate := false
			for _, m := range matches {
				if m == entry.Str {
					duplicate = true
					break
				}
			}
			if !duplicate {
				matches = append(matches, entry.Str)
			}
		}
	}
	if len(matches) > 0 {
		// Specific sorting to match upstream strace output for overlapping macros
		if len(matches) == 2 && matches[0] == "HIDIOCGVERSION" && matches[1] == "HIDIOCGRDESCSIZE" {
			matches[0], matches[1] = matches[1], matches[0]
		}
		return strings.Join(matches, " or "), true
	}
	if useUnknownEnumDecimalComment(xlatName) {
		return fmt.Sprintf("%d /* %s??? */", int32(val), table.Prefix), true
	}
	if useUnknownEnumDecimalFallback(xlatName, val) {
		return fmt.Sprintf("%d", int32(val)), true
	}
	formatVal := fmt.Sprintf("%#x", val)
	if val == 0 {
		formatVal = "0"
	}
	if xlatName == "x86_xfeature_bits" && val < 10 {
		formatVal = fmt.Sprintf("%d", val)
	}
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
		case 0:
			res = append(res, "O_RDONLY")
		case 1:
			res = append(res, "O_WRONLY")
		case 2:
			res = append(res, "O_RDWR")
		case 3:
			res = append(res, "O_ACCMODE")
		}
		handled |= accMode
	}

	for _, entry := range table.Entries {
		if entry.Val == 0 {
			continue
		}
		if (val & entry.Val) == entry.Val {
			if (handled & entry.Val) != entry.Val {
				res = append(res, entry.Str)
				handled |= entry.Val
			}
		}
	}

	if xlatName == "wait4_options" {
		for i := 0; i < len(res); i++ {
			for j := i + 1; j < len(res); j++ {
				if res[i] == "WSTOPPED" && res[j] == "WEXITED" {
					res[i], res[j] = res[j], res[i]
				}
			}
		}
	}

	if len(res) == 0 {
		if val == 0 {
			for _, entry := range table.Entries {
				if entry.Val == 0 {
					return entry.Str
				}
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

func decodeFanInitFlags(val uint64) string {
	v := uint32(val)
	class := v & 0xc
	handled := uint32(0)
	hasInitFlag := false
	var res []string

	switch class {
	case 0:
		res = append(res, "FAN_CLASS_NOTIF")
	case 4:
		res = append(res, "FAN_CLASS_CONTENT")
		handled |= class
	case 8:
		res = append(res, "FAN_CLASS_PRE_CONTENT")
		handled |= class
	default:
		res = append(res, fmt.Sprintf("%#x /* FAN_CLASS_??? */", class))
		handled |= class
	}

	for _, entry := range XlatTables["fan_init_flags"].Entries {
		if entry.Val == 0 || entry.Val == 4 || entry.Val == 8 {
			continue
		}
		bit := uint32(entry.Val)
		if (v & bit) == bit {
			res = append(res, entry.Str)
			handled |= bit
			hasInitFlag = true
		}
	}

	if remaining := v & ^handled; remaining != 0 {
		if hasInitFlag {
			res = append(res, fmt.Sprintf("%#x", remaining))
		} else {
			res = append(res, fmt.Sprintf("%#x /* FAN_??? */", remaining))
		}
	}
	return strings.Join(res, "|")
}

func xlatNameForValue(xlatName string, val uint64) (string, bool) {
	table, ok := XlatTables[xlatName]
	if !ok {
		return "", false
	}
	for _, entry := range table.Entries {
		if entry.Val == val {
			return entry.Str, true
		}
	}
	return "", false
}

func rawHexOrZero(val uint64) string {
	if val == 0 {
		return "0"
	}
	return fmt.Sprintf("%#x", val)
}

func decodeFutexBitset(val uint64) string {
	raw := rawHexOrZero(val)
	if XlatFormat == "raw" {
		return raw
	}
	name, ok := xlatNameForValue("futexbitset", val)
	if !ok {
		return raw
	}
	if XlatFormat == "verbose" {
		return fmt.Sprintf("%s /* %s */", raw, name)
	}
	return name
}

func decodeFutex2Flags(val uint64) string {
	v := uint32(val)
	raw := rawHexOrZero(uint64(v))
	if XlatFormat == "raw" {
		return raw
	}

	size := uint64(v & 3)
	sizeName, ok := xlatNameForValue("futex2_sizes", size)
	if !ok {
		sizeName = rawHexOrZero(size)
	}
	res := []string{sizeName}
	handled := uint32(3)

	if table, ok := XlatTables["futex2_flags"]; ok {
		for _, entry := range table.Entries {
			bit := uint32(entry.Val)
			if bit != 0 && (v&bit) == bit {
				res = append(res, entry.Str)
				handled |= bit
			}
		}
	}

	if remaining := v &^ handled; remaining != 0 {
		res = append(res, fmt.Sprintf("%#x", remaining))
	}

	decoded := strings.Join(res, "|")
	if XlatFormat == "verbose" {
		return fmt.Sprintf("%s /* %s */", raw, decoded)
	}
	return decoded
}

func decodeMemfdCreateFlags(val uint64) string {
	v := uint32(val)
	raw := rawHexOrZero(uint64(v))
	if v == 0 || XlatFormat == "raw" {
		return raw
	}

	const hugeShift = 26
	const hugeMask = uint32(0x3f << hugeShift)

	baseFlags := v &^ hugeMask
	hugeValue := (v & hugeMask) >> hugeShift
	var parts []string
	if table, ok := XlatTables["memfd_create_flags"]; ok && (baseFlags != 0 || hugeValue == 0) {
		parts = append(parts, decodeBitFlags(uint64(baseFlags), "memfd_create_flags", table))
	}
	if hugeValue != 0 {
		parts = append(parts, fmt.Sprintf("%d<<MFD_HUGE_SHIFT", hugeValue))
	}

	decoded := strings.Join(parts, "|")
	if XlatFormat == "verbose" {
		return fmt.Sprintf("%s /* %s */", raw, decoded)
	}
	return decoded
}

var XlatFormat string = "abbrev"

// DecodeFlags translates numeric flag values into human-readable strings.
// Impact: Core formatting helper for xlat flags. Used across default and specialized handlers.
func DecodeFlags(val uint64, xlatName string) string {
	checkRegisterBpfXlats()
	if decoded, ok := decodeSpecialXlat(val, xlatName); ok {
		return decoded
	}
	if XlatFormat == "raw" {
		return decodeRawXlat(val, xlatName)
	}
	return decodeNamedXlat(val, xlatName)
}

func decodeSpecialXlat(val uint64, xlatName string) (string, bool) {
	if xlatName == "hex_flags" {
		if val == 0 {
			return "0", true
		}
		return fmt.Sprintf("%#x", val), true
	}
	if xlatName == "futexbitset" {
		return decodeFutexBitset(val), true
	}
	if xlatName == "futex2_flags" {
		return decodeFutex2Flags(val), true
	}
	if xlatName == "memfd_create_flags" {
		return decodeMemfdCreateFlags(val), true
	}
	return "", false
}

func decodeRawXlat(val uint64, xlatName string) string {
	table, ok := XlatTables[xlatName]
	if ok && isEnumXlat(xlatName) {
		return rawEnumValue(val, xlatName)
	}
	if val == 0 && tableHasZeroEntry(table, ok) {
		return "0"
	}
	return rawHexOrZero(val)
}

func rawEnumValue(val uint64, xlatName string) string {
	if shouldTruncateXlatValueTo32(xlatName) {
		val = uint64(uint32(val))
	}
	if val == 0 {
		return "0"
	}
	if useRawEnumDecimalFormat(xlatName, val) {
		return fmt.Sprintf("%d", int32(val))
	}
	return fmt.Sprintf("%#x", val)
}

func tableHasZeroEntry(table XlatTable, ok bool) bool {
	if !ok {
		return false
	}
	for _, entry := range table.Entries {
		if entry.Val == 0 {
			return true
		}
	}
	return false
}

func decodeNamedXlat(val uint64, xlatName string) string {
	table, ok := XlatTables[xlatName]
	if !ok {
		return fmt.Sprintf("%#x", val)
	}

	if shouldTruncateXlatValueTo32(xlatName) {
		val = uint64(uint32(val))
	}
	if xlatName == "fan_init_flags" {
		return decodeFanInitFlags(val)
	}

	isEnum := isEnumXlat(xlatName)
	decoded := decodeEnumOrFlags(val, xlatName, table, isEnum)

	if XlatFormat == "verbose" {
		return verboseXlatValue(val, xlatName, decoded, isEnum)
	}

	return decoded
}

func decodeEnumOrFlags(val uint64, xlatName string, table XlatTable, isEnum bool) string {
	if isEnum {
		if s, ok := decodeEnum(val, xlatName, table); ok {
			return s
		}
		return fmt.Sprintf("%#x", val)
	}
	return decodeBitFlags(val, xlatName, table)
}

func verboseXlatValue(val uint64, xlatName, decoded string, isEnum bool) string {
	if strings.Contains(decoded, "/*") {
		return decoded
	}
	rawValStr := rawHexOrZero(val)
	if val != 0 && isEnum && useRawEnumDecimalFormat(xlatName, val) {
		rawValStr = fmt.Sprintf("%d", int32(val))
	}
	if decoded == rawValStr {
		return decoded
	}
	return fmt.Sprintf("%s /* %s */", rawValStr, decoded)
}
