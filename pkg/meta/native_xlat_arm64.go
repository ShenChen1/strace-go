package meta

import "golang.org/x/sys/unix"

// Raw kernel O_LARGEFILE differs from the libc/x/sys LP64 constant (zero).
const nativeRawOLargefile = 0x20000

var nativeExcludedXlatNames = map[string]bool{"MAP_32BIT": true, "MAP_ABOVE4G": true}
var nativeXlatAdditions = map[string][]XlatVal{
	"mmap_prot":   {{Val: unix.PROT_BTI, Str: "PROT_BTI"}, {Val: unix.PROT_MTE, Str: "PROT_MTE"}},
	"mmap_prot64": {{Val: unix.PROT_BTI, Str: "PROT_BTI"}, {Val: unix.PROT_MTE, Str: "PROT_MTE"}},
}
