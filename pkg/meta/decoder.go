package meta

import (
	"fmt"
	"strings"
)

func DecodeFlags(val uint64, xlatName string) string {
	var res []string
	
	// Check if this xlat exists
	table, ok := XlatTables[xlatName]
	if !ok {
		return fmt.Sprintf("%#x", val)
	}

	// For specific known tables that don't just use simple bitmasks
	if xlatName == "open_mode_flags" {
		// handle access mode part first (O_RDONLY, O_WRONLY, O_RDWR)
		accMode := val & 3
		for _, x := range XlatTables["open_access_modes"] {
			if x.Val == accMode && x.Str != "O_ACCMODE" {
				res = append(res, x.Str)
				break
			}
		}
		val &^= 3 // Clear the lower 2 bits
	}

	// First pass: look for zero value match if val is exactly 0
	if val == 0 {
		for _, x := range table {
			if x.Val == 0 {
				return x.Str
			}
		}
		if len(res) == 0 {
			return "0"
		}
		return strings.Join(res, "|")
	}

	// Second pass: extract flags
	handled := uint64(0)
	for _, x := range table {
		if x.Val == 0 {
			continue // skip 0 values since val != 0
		}
		// If exact match
		if val == x.Val {
			res = append(res, x.Str)
			handled |= x.Val
			break
		}
		// If bitwise flag
		if val&x.Val == x.Val {
			// Ensure we don't match overlapping smaller flags if a larger one is matched
			// E.g. if a flag is just a single bit, we match it.
			// This basic implementation assumes non-overlapping bitflags except specific combinations.
			// Strace actually has logic to pick the largest mask first, but for our simple flags it's ok.
			res = append(res, x.Str)
			handled |= x.Val
		}
	}

	if val&^handled != 0 {
		res = append(res, fmt.Sprintf("%#x", val&^handled))
	}

	if len(res) == 0 {
		return fmt.Sprintf("%#x", val)
	}

	return strings.Join(res, "|")
}
