package handler

import "strace-go/pkg/meta"

func registerBuiltinMountPath(r *Registry) {
	r.Register("open_tree", &OpenTreeHandler{})
	r.Register("move_mount", &MoveMountHandler{})
}

// OpenTreeHandler formats the path snapshot and the 32-bit syscall flags.
type OpenTreeHandler struct{}

func (h *OpenTreeHandler) Handle(ctx *Context) Result {
	return formatMountPathSyscall(ctx, 2, 2, "open_tree_flags")
}

// MoveMountHandler formats both probe-site path snapshots and mount flags.
type MoveMountHandler struct{}

func (h *MoveMountHandler) Handle(ctx *Context) Result {
	return formatMountPathSyscall(ctx, 4, 4, "move_mount_flags")
}

func formatMountPathSyscall(ctx *Context, scalarArgs int, flagsArg int, xlat string) Result {
	res := (&DefaultHandler{}).HandleWithCount(ctx, scalarArgs)
	flags := uint64(uint32(ctx.Args[flagsArg]))
	res.ArgParts = append(res.ArgParts, meta.DecodeFlags(flags, xlat))
	return res
}
