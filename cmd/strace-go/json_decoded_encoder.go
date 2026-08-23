package main

import "strace-go/pkg/handler"

func appendJSONRawSyscallEvent(dst []byte, ev syscallEventContext) []byte {
	view := ev.eventView()
	scMeta := ev.effectiveSyscallMeta()
	failed, errno := syscallFailure(view.ret)
	return appendJSONSyscallWireEvent(dst, jsonSyscallWireEvent{
		eventVersion:    view.eventVersion,
		eventType:       view.eventType,
		eventFlags:      view.eventFlags,
		pid:             view.pid,
		tid:             view.tid,
		sysID:           view.sysID,
		syscall:         scMeta.Name,
		args:            view.args,
		ret:             view.ret,
		failed:          failed,
		errno:           int64(errno),
		duration:        view.duration,
		enterTime:       view.enterTime,
		stackID:         view.stackID,
		payloadSections: ev.outputPayloadSections(),
		probeRetEnter:   view.probeRetEnter,
		probeRetExit:    view.probeRetExit,
	})
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
	return appendJSONSyscallWireEvent(dst, jsonSyscallWireEvent{
		eventVersion:      view.eventVersion,
		eventType:         view.eventType,
		eventFlags:        view.eventFlags,
		pid:               view.pid,
		tid:               view.tid,
		sysID:             view.sysID,
		syscall:           scMeta.Name,
		args:              view.args,
		argText:           res.ArgParts,
		ret:               view.ret,
		hasReturnText:     true,
		returnTextName:    ev.syscallName(),
		returnTextRet:     view.ret,
		returnTextResult:  res,
		returnTextContext: ev.handlerContextForFormatting(),
		failed:            failed,
		errno:             int64(errno),
		duration:          view.duration,
		enterTime:         view.enterTime,
		stackID:           view.stackID,
		payloadSections:   ev.decodedPayloadSections(),
		probeRetEnter:     view.probeRetEnter,
		probeRetExit:      view.probeRetExit,
		pairedEnter:       ev.pairedGenericEnter(),
	})
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
	return appendJSONPayloadSectionFields(dst, jsonPayloadSectionFields{
		Kind:      string(section.Kind),
		Direction: string(section.Direction),
		ArgIndex:  int64(section.ArgIndex),
		UserPtr:   section.UserPtr,
		UserLen:   uint64(section.UserLen),
		CopiedLen: uint64(section.CopiedLen),
		ProbeRet:  int64(section.ProbeRet),
		RawData:   section.Data,
	})
}
