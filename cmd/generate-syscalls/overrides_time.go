package main

func init() {
	manualOverrides["utime"] = SyscallMeta{
		Name:     "utime",
		Args:     []string{"filename", "times"},
		ArgTypes: []string{"const char *", "struct utimbuf *"},
	}
	manualOverrides["utimes"] = SyscallMeta{
		Name:     "utimes",
		Args:     []string{"filename", "times"},
		ArgTypes: []string{"const char *", "struct timeval *"},
	}
	manualOverrides["futimesat"] = SyscallMeta{
		Name:     "futimesat",
		Args:     []string{"dfd", "filename", "times"},
		ArgTypes: []string{"int", "const char *", "struct timeval *"},
	}
}
