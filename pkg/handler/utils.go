package handler

import "fmt"

// formatPtr formats a pointer field as NULL or hex.
func formatPtr(name string, val uint64) string {
	if val == 0 {
		return name + "=NULL"
	}
	return fmt.Sprintf("%s=%#x", name, val)
}
