package handler

// builtinRegistry is built once during package initialization and never used
// as a runtime mutation point. NewRegistry clones it for each trace session.
var builtinRegistry = buildBuiltinRegistry()

func buildBuiltinRegistry() *Registry {
	registry := &Registry{handlers: make(map[string]Handler)}

	// Keep the historical file-order registration sequence. Decoder lookup is
	// first-match, so this order is part of the formatter behavior contract.
	registerBuiltinAio(registry)
	registerBuiltinArchPrctl(registry)
	registerBuiltinBpf(registry)
	registerBuiltinCachestat(registry)
	registerBuiltinCapability(registry)
	registerBuiltinCopyFileRange(registry)
	registerBuiltinDefault(registry)
	registerBuiltinEpoll(registry)
	registerBuiltinFcntl(registry)
	registerBuiltinFs(registry)
	registerBuiltinFutex(registry)
	registerBuiltinFutex2(registry)
	registerBuiltinGetRobustList(registry)
	registerBuiltinIo(registry)
	registerBuiltinIoctl(registry)
	registerBuiltinMountPath(registry)
	registerBuiltinMountQuery(registry)
	registerBuiltinMountSetattr(registry)
	registerBuiltinMsg(registry)
	registerBuiltinNetwork(registry)
	registerBuiltinOpenat2(registry)
	registerBuiltinPrctl(registry)
	registerBuiltinProcess(registry)
	registerBuiltinProcessMadvise(registry)
	registerBuiltinQuota(registry)
	registerBuiltinSelect(registry)
	registerBuiltinSendfile(registry)
	registerBuiltinSignal(registry)
	registerBuiltinStatx(registry)
	registerBuiltinSysFile(registry)
	registerBuiltinSysMem(registry)
	registerBuiltinTime(registry)
	registerBuiltinTypeMisc(registry)
	registerBuiltinTypeStat(registry)
	registerBuiltinTypeString(registry)
	registerBuiltinTypeTime(registry)
	registerBuiltinWaitid(registry)

	return registry
}
