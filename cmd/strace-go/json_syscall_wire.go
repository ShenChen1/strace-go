package main

import "strace-go/pkg/handler"

// jsonSyscallWireEvent is the already-decided syscall output. It contains no
// session state, so the hot writer can encode raw and decoded events alike.
type jsonSyscallWireEvent struct {
	eventVersion      uint16
	eventType         uint16
	eventFlags        uint32
	pid               uint32
	tid               uint32
	sysID             uint32
	syscall           string
	args              [6]uint64
	argText           []string
	ret               int64
	hasReturnText     bool
	returnTextName    string
	returnTextRet     int64
	returnTextResult  handler.Result
	returnTextContext *handler.Context
	failed            bool
	errno             int64
	duration          uint64
	enterTime         uint64
	stackID           int32
	payloadSections   []handler.PayloadSection
	probeRetEnter     int32
	probeRetExit      int32
	pairedEnter       bool
}

func appendJSONSyscallWireEvent(dst []byte, event jsonSyscallWireEvent) []byte {
	dst = append(dst, `{"type":"syscall"`...)
	dst = appendJSONSyscallWireHeader(dst, event)
	dst = appendJSONSyscallWireIdentity(dst, event)
	dst = appendJSONSyscallWireReturn(dst, event)
	dst = appendJSONSyscallWireMetadata(dst, event)
	return append(dst, "}\n"...)
}

func appendJSONSyscallWireHeader(dst []byte, event jsonSyscallWireEvent) []byte {
	if event.eventVersion != 0 {
		dst = append(dst, `,"event_version":`...)
		dst = appendJSONUint(dst, uint64(event.eventVersion))
	}
	dst = append(dst, `,"event_type":"`...)
	dst = append(dst, bpfEventTypeNameFromID(event.eventType)...)
	dst = append(dst, '"')
	if event.eventType != 0 {
		dst = append(dst, `,"event_type_id":`...)
		dst = appendJSONUint(dst, uint64(event.eventType))
	}
	if event.eventFlags != 0 {
		dst = append(dst, `,"event_flags":`...)
		dst = appendJSONUint(dst, uint64(event.eventFlags))
	}
	return dst
}

func appendJSONSyscallWireIdentity(dst []byte, event jsonSyscallWireEvent) []byte {
	dst = append(dst, `,"pid":`...)
	dst = appendJSONUint(dst, uint64(event.pid))
	dst = append(dst, `,"tid":`...)
	dst = appendJSONUint(dst, uint64(event.tid))
	dst = append(dst, `,"sys_id":`...)
	dst = appendJSONUint(dst, uint64(event.sysID))
	dst = append(dst, `,"syscall":`...)
	dst = appendJSONSyscallName(dst, event.syscall)
	dst = append(dst, `,"args":`...)
	dst = appendJSONUint64Array(dst, event.args)
	if len(event.argText) > 0 {
		dst = append(dst, `,"arg_text":`...)
		dst = appendJSONStringArray(dst, event.argText)
	}
	return dst
}

func appendJSONSyscallWireReturn(dst []byte, event jsonSyscallWireEvent) []byte {
	dst = append(dst, `,"ret":`...)
	dst = appendJSONInt(dst, event.ret)
	if event.hasReturnText {
		dst = append(dst, `,"return_text":`...)
		dst = appendJSONSyscallReturn(
			dst,
			event.returnTextName,
			event.returnTextRet,
			event.returnTextResult,
			event.returnTextContext,
		)
	}
	dst = append(dst, `,"failed":`...)
	if event.failed {
		dst = append(dst, "true"...)
	} else {
		dst = append(dst, "false"...)
	}
	if event.errno != 0 {
		dst = append(dst, `,"errno":`...)
		dst = appendJSONInt(dst, event.errno)
	}
	return dst
}

func appendJSONSyscallWireMetadata(dst []byte, event jsonSyscallWireEvent) []byte {
	dst = append(dst, `,"duration_ns":`...)
	dst = appendJSONUint(dst, event.duration)
	dst = append(dst, `,"enter_time_ns":`...)
	dst = appendJSONUint(dst, event.enterTime)
	dst = append(dst, `,"stack_id":`...)
	dst = appendJSONInt(dst, int64(event.stackID))
	if len(event.payloadSections) > 0 {
		dst = append(dst, `,"payload_sections":`...)
		dst = appendJSONHandlerPayloadSections(dst, event.payloadSections)
	}
	dst = append(dst, `,"probe_ret_enter":`...)
	dst = appendJSONInt(dst, int64(event.probeRetEnter))
	dst = append(dst, `,"probe_ret_exit":`...)
	dst = appendJSONInt(dst, int64(event.probeRetExit))
	if event.pairedEnter {
		dst = append(dst, `,"paired_enter":true`...)
	}
	return dst
}
