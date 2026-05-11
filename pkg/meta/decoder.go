package meta

import (
	"fmt"
	"strings"
)

func DecodeFlags(val uint64, xlatName string) string {
	table, ok := XlatTables[xlatName]
	if !ok { return fmt.Sprintf("%#x", val) }

	isEnum := strings.HasSuffix(xlatName, "vals") || strings.HasSuffix(xlatName, "options") || xlatName == "socktypes" || xlatName == "bpf_commands" || xlatName == "archvals" || xlatName == "addrfams" || xlatName == "open_access_modes" || xlatName == "whence" || xlatName == "x86_xfeature_bits" || xlatName == "epollctls" || xlatName == "term_cmds_overlapping"

	if isEnum {
		for _, entry := range table.Entries {
			if entry.Val == val { return entry.Str }
		}
		// Special case for bitmask-enums
		if xlatName != "adjtimex_status" && xlatName != "open_mode_flags" {
			if val == 0 { return "0" }
			formatVal := fmt.Sprintf("%#x", val)
			if xlatName == "x86_xfeature_bits" && val < 10 { formatVal = fmt.Sprintf("%d", val) }
			if table.Prefix != "" {
				return fmt.Sprintf("%s /* %s??? */", formatVal, table.Prefix)
			}
			return fmt.Sprintf("%s /* ??? */", formatVal)
		}
	}

	var res []string
	handled := uint64(0)

	// For open flags, handle ACCMODE part first to match strace behavior
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

	// Use original table order to preserve strace canonical order
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
		formatVal := fmt.Sprintf("%#x", val)
		if table.Prefix != "" {
			return fmt.Sprintf("%s /* %s??? */", formatVal, table.Prefix)
		}
		return fmt.Sprintf("%s /* ??? */", formatVal)
	}

	if handled != val && val != 0 {
		// Only append hex if there's remaining unhandled bits
		remaining := val & ^handled
		if remaining != 0 {
			res = append(res, fmt.Sprintf("%#x", remaining))
		}
	}

	return strings.Join(res, "|")
}
