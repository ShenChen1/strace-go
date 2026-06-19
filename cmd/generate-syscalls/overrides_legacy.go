package main

func init() {
	manualOverrides["ustat"] = SyscallMeta{
		Name:     "ustat",
		Args:     []string{"dev", "ubuf"},
		ArgTypes: []string{"dev_t", "struct ustat *"},
	}
}
