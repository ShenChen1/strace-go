package handler

import "strace-go/pkg/meta"

func catalogForContext(ctx *Context) meta.CatalogPort {
	if ctx == nil {
		return nil
	}
	return ctx.Meta
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
