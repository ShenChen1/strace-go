package handler

func init() {
	Register("open", &OpenHandler{})
	Register("openat", &OpenHandler{})
	Register("mknod", &MknodHandler{})
	Register("mknodat", &MknodHandler{})
}

type OpenHandler struct{}

func (h *OpenHandler) Handle(ctx *Context) Result {
	argCount := len(ctx.ScMeta.ArgTypes)
	flags := uint32(ctx.Args[1])
	if ctx.ScMeta.Name == "openat" {
		flags = uint32(ctx.Args[2])
	}
	hasMode := (flags&0100 != 0) || (flags&020000000 != 0) // O_CREAT or O_TMPFILE
	if !hasMode {
		if ctx.ScMeta.Name == "open" {
			argCount = 2
		} else {
			argCount = 3
		}
	}
	return handleDefaultWithCount(ctx, argCount)
}

type MknodHandler struct{}

func (h *MknodHandler) Handle(ctx *Context) Result {
	argCount := len(ctx.ScMeta.ArgTypes)
	modeIdx := 1
	if ctx.ScMeta.Name == "mknodat" {
		modeIdx = 2
	}
	mode := uint16(ctx.Args[modeIdx])
	typeVal := mode & 0170000
	if typeVal != 0020000 && typeVal != 0060000 { // S_IFCHR, S_IFBLK
		if ctx.ScMeta.Name == "mknod" {
			argCount = 2
		} else {
			argCount = 3
		}
	}
	return handleDefaultWithCount(ctx, argCount)
}
