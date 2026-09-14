package meta

// Raw kernel O_LARGEFILE differs from the libc/x/sys LP64 constant (zero).
const nativeRawOLargefile = 0x8000

var nativeExcludedXlatNames = map[string]bool{}
var nativeXlatAdditions = map[string][]XlatVal{}
