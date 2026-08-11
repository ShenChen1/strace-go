package handler

import "strace-go/pkg/meta"

func catalogForContext(ctx *Context) *meta.Catalog {
	if ctx != nil && ctx.Meta != nil {
		return ctx.Meta
	}
	if ctx != nil && ctx.Opts != nil {
		return meta.NewCatalog(ctx.Opts.XlatFormat)
	}
	return meta.NewCatalog("abbrev")
}

func decodeFlags(ctx *Context, value uint64, tableName string) string {
	return catalogForContext(ctx).DecodeFlags(value, tableName)
}

func xlatTable(ctx *Context, tableName string) (meta.XlatTable, bool) {
	return catalogForContext(ctx).Table(tableName)
}

func syscallArgXlat(ctx *Context, syscallName, argName string) (string, bool) {
	return catalogForContext(ctx).SyscallArgXlat(syscallName, argName)
}

func xlatFormat(ctx *Context) string {
	return catalogForContext(ctx).Format()
}
