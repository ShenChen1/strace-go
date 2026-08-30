package meta

import "strings"

var enumXlatNames = map[string]bool{
	"addrfams":              true,
	"archvals":              true,
	"bpf_attach_type":       true,
	"bpf_commands":          true,
	"bpf_fd_type":           true,
	"bpf_map_types":         true,
	"bpf_prog_types":        true,
	"bpf_stats_type":        true,
	"clocknames":            true,
	"epollctls":             true,
	"fcntlcmds":             true,
	"fsconfig_cmds":         true,
	"fsmagic":               true,
	"futexops":              true,
	"ioctl_cmds":            true,
	"itimer_which":          true,
	"keyctl_commands":       true,
	"key_spec":              true,
	"listmount_mnt_id":      true,
	"madvise_cmds":          true,
	"open_access_modes":     true,
	"netlink_protocols":     true,
	"protocols":             true,
	"quota_formats":         true,
	"quotacmds":             true,
	"quotatypes":            true,
	"resources":             true,
	"signalnames":           true,
	"socktypes":             true,
	"socketlayers":          true,
	"term_cmds_overlapping": true,
	"waitid_types":          true,
	"whence":                true,
	"x86_xfeature_bits":     true,
}

var bitflagXlatNames = map[string]bool{
	"clone3_flags":  true,
	"wait4_options": true,
}

var unknownEnumDecimalExcluded = map[string]bool{
	"archvals":          true,
	"clocknames":        true,
	"fcntlcmds":         true,
	"fsconfig_cmds":     true,
	"ioctl_cmds":        true,
	"madvise_cmds":      true,
	"resources":         true,
	"sock_options":      true,
	"socketlayers":      true,
	"x86_xfeature_bits": true,
}

var rawEnumDecimalExcluded = map[string]bool{
	"archvals":          true,
	"clocknames":        true,
	"fcntlcmds":         true,
	"ioctl_cmds":        true,
	"madvise_cmds":      true,
	"resources":         true,
	"sock_options":      true,
	"socketlayers":      true,
	"x86_xfeature_bits": true,
}

var unknownEnumDecimalComment = map[string]bool{
	"sockopt_txrehash_vals": true,
}

var fullWidthXlatNames = map[string]bool{
	"clone3_flags":              true,
	"mmap_prot64":               true,
	"pkey_access_rights":        true,
	"statx_attrs":               true,
	"statmount_mask":            true,
	"statmount_mnt_propagation": true,
	"listmount_mnt_id":          true,
	"unshare_flags":             true,
}

func isEnumXlat(xlatName string) bool {
	if xlatName == "mount_attr_propagation" {
		return true
	}
	if bitflagXlatNames[xlatName] {
		return false
	}
	return strings.HasSuffix(xlatName, "vals") ||
		strings.HasSuffix(xlatName, "options") ||
		enumXlatNames[xlatName]
}

func useUnknownEnumDecimalFallback(xlatName string, val uint64) bool {
	if xlatName == "signalnames" || xlatName == "key_spec" {
		return true
	}
	return val < 100 &&
		!strings.HasPrefix(xlatName, "bpf_") &&
		!unknownEnumDecimalExcluded[xlatName]
}

func useUnknownEnumDecimalComment(xlatName string) bool {
	return unknownEnumDecimalComment[xlatName]
}

func useRawEnumDecimalFormat(xlatName string, val uint64) bool {
	if unknownEnumDecimalComment[xlatName] {
		return true
	}
	if xlatName == "signalnames" || xlatName == "key_spec" {
		return true
	}
	return val < 100 &&
		!strings.HasPrefix(xlatName, "bpf_") &&
		!rawEnumDecimalExcluded[xlatName]
}

func shouldTruncateXlatValueTo32(xlatName string) bool {
	if xlatName == "mount_attr_attr" || xlatName == "mount_attr_propagation" {
		return false
	}
	return !fullWidthXlatNames[xlatName] && !strings.HasPrefix(xlatName, "bpf_")
}
