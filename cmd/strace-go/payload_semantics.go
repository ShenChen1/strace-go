package main

const (
	fdArrayPayloadSize        = 8
	pollPayloadFdSize         = 8
	selectPayloadFdSetSize    = 128
	selectPayloadFdSetArgBase = 1
	selectPayloadFdSetArgLast = 3
)

func simplePathPayloadArgIndex(scName string) (int, bool) {
	switch scName {
	case "open", "creat", "access", "chdir", "chroot", "chmod", "chown", "lchown",
		"mkdir", "mknod", "rmdir", "unlink", "swapon", "swapoff", "acct", "truncate", "fsopen":
		return 0, true
	case "mkdirat", "mknodat", "chmodat", "fchmodat", "faccessat", "faccessat2",
		"unlinkat", "fchownat", "fspick":
		return 1, true
	default:
		return 0, false
	}
}
