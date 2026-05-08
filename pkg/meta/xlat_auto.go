package meta

type XlatVal struct {
	Val uint64
	Str string
}

var XlatTables = map[string][]XlatVal{
	"open_mode_flags": {
		{Val: 64, Str: "O_CREAT"},
		{Val: 128, Str: "O_EXCL"},
		{Val: 256, Str: "O_NOCTTY"},
		{Val: 512, Str: "O_TRUNC"},
		{Val: 1024, Str: "O_APPEND"},
		{Val: 2048, Str: "O_NONBLOCK"},
		{Val: 1052672, Str: "O_SYNC"},
		{Val: 4096, Str: "O_DSYNC"},
		{Val: 131072, Str: "O_NOFOLLOW"},
		{Val: 524288, Str: "O_CLOEXEC"},
		{Val: 4259840, Str: "__O_TMPFILE"},
		{Val: 65536, Str: "O_DIRECTORY"},
		{Val: 8192, Str: "FASYNC"},
	},
	"open_access_modes": {
		{Val: 0, Str: "O_RDONLY"},
		{Val: 1, Str: "O_WRONLY"},
		{Val: 2, Str: "O_RDWR"},
		{Val: 3, Str: "O_ACCMODE"},
	},
	"access_modes": {
		{Val: 0, Str: "F_OK"},
		{Val: 4, Str: "R_OK"},
		{Val: 2, Str: "W_OK"},
		{Val: 1, Str: "X_OK"},
	},
}

var SyscallArgXlatMap = map[string]map[string]string{
	"open": {
		"flags": "open_mode_flags",
	},
	"openat": {
		"flags": "open_mode_flags",
	},
	"access": {
		"mode": "access_modes",
	},
	"faccessat": {
		"mode": "access_modes",
	},
}
