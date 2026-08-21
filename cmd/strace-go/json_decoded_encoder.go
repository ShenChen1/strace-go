package main

import "strace-go/pkg/handler"

func appendJSONRawSyscallEvent(dst []byte, ev syscallEventContext) []byte {
	view := ev.eventView()
	scMeta := ev.effectiveSyscallMeta()
	failed, errno := syscallFailure(view.ret)
	builder := jsonLineBuilder{data: dst}
	builder.beginObject()
	builder.trustedStringField(jsonFieldType, "syscall")
	builder.uintField(jsonFieldEventVersion, uint64(view.eventVersion), true)
	builder.trustedStringField(jsonFieldEventType, bpfEventTypeNameFromID(view.eventType))
	builder.uintField(jsonFieldEventTypeID, uint64(view.eventType), true)
	builder.uintField(jsonFieldEventFlags, uint64(view.eventFlags), true)
	builder.uintField(jsonFieldPID, uint64(view.pid), false)
	builder.uintField(jsonFieldTID, uint64(view.tid), false)
	builder.uintField(jsonFieldSysID, uint64(view.sysID), false)
	builder.syscallNameField(jsonFieldSyscall, scMeta.Name)
	builder.uint64ArrayField(jsonFieldArgs, view.args)
	builder.intField(jsonFieldRet, view.ret)
	builder.boolField(jsonFieldFailed, failed, false)
	builder.intFieldIfNonZero(jsonFieldErrno, int64(errno))
	builder.uintField(jsonFieldDurationNS, view.duration, false)
	builder.uintField(jsonFieldEnterTimeNS, view.enterTime, false)
	builder.intField(jsonFieldStackID, int64(view.stackID))
	if sections := ev.outputPayloadSections(); len(sections) > 0 {
		builder.beginFieldToken(jsonFieldPayloadSections)
		builder.data = appendJSONHandlerPayloadSections(builder.data, sections)
	}
	builder.intField(jsonFieldProbeRetEnter, int64(view.probeRetEnter))
	builder.intField(jsonFieldProbeRetExit, int64(view.probeRetExit))
	builder.boolField(jsonFieldPairedEnter, false, true)
	return builder.endLine()
}

// appendJSONDecodedSyscallEvent keeps the high-frequency decoded path in the
// event context and avoids materializing an intermediate JSON event model.
func appendJSONDecodedSyscallEvent(
	dst []byte,
	ev syscallEventContext,
	res handler.Result,
) []byte {
	if canUsePlainDecodedJSON(ev, res) {
		return appendJSONPlainDecodedSyscallEvent(dst, ev, res)
	}
	view := ev.eventView()
	scMeta := ev.effectiveSyscallMeta()
	failed, errno := syscallFailure(view.ret)
	builder := jsonLineBuilder{data: dst}
	builder.beginObject()
	builder.trustedStringField(jsonFieldType, "syscall")
	builder.uintField(jsonFieldEventVersion, uint64(view.eventVersion), true)
	builder.trustedStringField(jsonFieldEventType, bpfEventTypeNameFromID(view.eventType))
	builder.uintField(jsonFieldEventTypeID, uint64(view.eventType), true)
	builder.uintField(jsonFieldEventFlags, uint64(view.eventFlags), true)
	builder.uintField(jsonFieldPID, uint64(view.pid), false)
	builder.uintField(jsonFieldTID, uint64(view.tid), false)
	builder.uintField(jsonFieldSysID, uint64(view.sysID), false)
	builder.syscallNameField(jsonFieldSyscall, scMeta.Name)
	builder.uint64ArrayField(jsonFieldArgs, view.args)
	builder.stringArrayField(jsonFieldArgText, res.ArgParts)
	builder.intField(jsonFieldRet, view.ret)
	builder.beginFieldToken(jsonFieldReturnText)
	builder.data = appendJSONSyscallReturn(
		builder.data,
		ev.syscallName(),
		view.ret,
		res,
		ev.handlerContextForFormatting(),
	)
	builder.boolField(jsonFieldFailed, failed, false)
	builder.intFieldIfNonZero(jsonFieldErrno, int64(errno))
	builder.uintField(jsonFieldDurationNS, view.duration, false)
	builder.uintField(jsonFieldEnterTimeNS, view.enterTime, false)
	builder.intField(jsonFieldStackID, int64(view.stackID))
	if sections := ev.decodedPayloadSections(); len(sections) > 0 {
		builder.beginFieldToken(jsonFieldPayloadSections)
		builder.data = appendJSONHandlerPayloadSections(builder.data, sections)
	}
	builder.intField(jsonFieldProbeRetEnter, int64(view.probeRetEnter))
	builder.intField(jsonFieldProbeRetExit, int64(view.probeRetExit))
	builder.boolField(jsonFieldPairedEnter, ev.pairedGenericEnter(), true)
	return builder.endLine()
}

func canUsePlainDecodedJSON(ev syscallEventContext, res handler.Result) bool {
	if ev.handlerContext != nil || len(ev.outputPayloadSections()) > 0 {
		return false
	}
	if len(res.ArgParts) > 0 || res.HexDumpStr != "" || res.ReturnDesc != "" || res.ShowEmptyReturnDesc {
		return false
	}
	return canAppendPlainSyscallReturn(ev.syscallName(), ev.eventView().ret, res, nil)
}

func appendJSONPlainDecodedSyscallEvent(
	dst []byte,
	ev syscallEventContext,
	res handler.Result,
) []byte {
	view := ev.eventView()
	scMeta := ev.effectiveSyscallMeta()
	failed, errno := syscallFailure(view.ret)
	dst = append(dst, `{"type":"syscall"`...)
	if view.eventVersion != 0 {
		dst = append(dst, `,"event_version":`...)
		dst = appendJSONUint(dst, uint64(view.eventVersion))
	}
	dst = append(dst, `,"event_type":"`...)
	dst = append(dst, bpfEventTypeNameFromID(view.eventType)...)
	dst = append(dst, `"`...)
	if view.eventType != 0 {
		dst = append(dst, `,"event_type_id":`...)
		dst = appendJSONUint(dst, uint64(view.eventType))
	}
	if view.eventFlags != 0 {
		dst = append(dst, `,"event_flags":`...)
		dst = appendJSONUint(dst, uint64(view.eventFlags))
	}
	dst = append(dst, `,"pid":`...)
	dst = appendJSONUint(dst, uint64(view.pid))
	dst = append(dst, `,"tid":`...)
	dst = appendJSONUint(dst, uint64(view.tid))
	dst = append(dst, `,"sys_id":`...)
	dst = appendJSONUint(dst, uint64(view.sysID))
	dst = append(dst, `,"syscall":`...)
	dst = appendJSONSyscallName(dst, scMeta.Name)
	dst = append(dst, `,"args":`...)
	dst = appendJSONUint64Array(dst, view.args)
	dst = append(dst, `,"ret":`...)
	dst = appendJSONInt(dst, view.ret)
	dst = append(dst, `,"return_text":`...)
	dst = appendJSONSyscallReturn(dst, ev.syscallName(), view.ret, res, nil)
	dst = append(dst, `,"failed":`...)
	if failed {
		dst = append(dst, "true"...)
	} else {
		dst = append(dst, "false"...)
	}
	if errno != 0 {
		dst = append(dst, `,"errno":`...)
		dst = appendJSONInt(dst, int64(errno))
	}
	dst = append(dst, `,"duration_ns":`...)
	dst = appendJSONUint(dst, view.duration)
	dst = append(dst, `,"enter_time_ns":`...)
	dst = appendJSONUint(dst, view.enterTime)
	dst = append(dst, `,"stack_id":`...)
	dst = appendJSONInt(dst, int64(view.stackID))
	dst = append(dst, `,"probe_ret_enter":`...)
	dst = appendJSONInt(dst, int64(view.probeRetEnter))
	dst = append(dst, `,"probe_ret_exit":`...)
	dst = appendJSONInt(dst, int64(view.probeRetExit))
	if ev.pairedGenericEnter() {
		dst = append(dst, `,"paired_enter":true`...)
	}
	return append(dst, "}\n"...)
}

func appendJSONUint64Array(dst []byte, values [6]uint64) []byte {
	if values == ([6]uint64{}) {
		return append(dst, "[0,0,0,0,0,0]"...)
	}
	dst = append(dst, '[')
	for index, value := range values {
		if index > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONUint(dst, value)
	}
	return append(dst, ']')
}

func appendJSONHandlerPayloadSections(
	dst []byte,
	sections []handler.PayloadSection,
) []byte {
	dst = append(dst, '[')
	for index, section := range sections {
		if index > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONHandlerPayloadSection(dst, section)
	}
	return append(dst, ']')
}

func appendJSONHandlerPayloadSection(
	dst []byte,
	section handler.PayloadSection,
) []byte {
	builder := jsonLineBuilder{data: dst}
	builder.beginObject()
	builder.stringField(jsonFieldKind, string(section.Kind), false)
	builder.stringField(jsonFieldDirection, string(section.Direction), false)
	builder.intField(jsonFieldArgIndex, int64(section.ArgIndex))
	builder.uintField(jsonFieldUserPtr, section.UserPtr, true)
	builder.uintField(jsonFieldUserLen, uint64(section.UserLen), true)
	builder.uintField(jsonFieldCopiedLen, uint64(section.CopiedLen), false)
	builder.intField(jsonFieldProbeRet, int64(section.ProbeRet))
	builder.base64Field(jsonFieldDataBase64, "", section.Data)
	builder.endObject()
	return builder.data
}
