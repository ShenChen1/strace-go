package main

import (
	"encoding/base64"
	"strconv"
	"unicode/utf8"

	"strace-go/pkg/handler"
)

const (
	jsonFieldType            = `"type":`
	jsonFieldEventVersion    = `"event_version":`
	jsonFieldEventType       = `"event_type":`
	jsonFieldEventTypeID     = `"event_type_id":`
	jsonFieldEventFlags      = `"event_flags":`
	jsonFieldPID             = `"pid":`
	jsonFieldTID             = `"tid":`
	jsonFieldSysID           = `"sys_id":`
	jsonFieldSyscall         = `"syscall":`
	jsonFieldArgs            = `"args":`
	jsonFieldArgText         = `"arg_text":`
	jsonFieldRet             = `"ret":`
	jsonFieldReturnText      = `"return_text":`
	jsonFieldFailed          = `"failed":`
	jsonFieldErrno           = `"errno":`
	jsonFieldDurationNS      = `"duration_ns":`
	jsonFieldEnterTimeNS     = `"enter_time_ns":`
	jsonFieldStackID         = `"stack_id":`
	jsonFieldPayloadSections = `"payload_sections":`
	jsonFieldProbeRetEnter   = `"probe_ret_enter":`
	jsonFieldProbeRetExit    = `"probe_ret_exit":`
	jsonFieldPairedEnter     = `"paired_enter":`
	jsonFieldKind            = `"kind":`
	jsonFieldDirection       = `"direction":`
	jsonFieldArgIndex        = `"arg_index":`
	jsonFieldUserPtr         = `"user_ptr":`
	jsonFieldUserLen         = `"user_len":`
	jsonFieldCopiedLen       = `"copied_len":`
	jsonFieldProbeRet        = `"probe_ret":`
	jsonFieldDataBase64      = `"data_base64":`
)

type jsonLineBuilder struct {
	data  []byte
	first bool
}

func (b *jsonLineBuilder) beginObject() {
	b.data = append(b.data, '{')
	b.first = true
}

func (b *jsonLineBuilder) beginFieldToken(token string) {
	if !b.first {
		b.data = append(b.data, ',')
	}
	b.first = false
	b.data = append(b.data, token...)
}

func (b *jsonLineBuilder) stringField(token, value string, omit bool) {
	if omit && value == "" {
		return
	}
	b.beginFieldToken(token)
	b.data = appendJSONString(b.data, value)
}

func (b *jsonLineBuilder) uintField(token string, value uint64, omit bool) {
	if omit && value == 0 {
		return
	}
	b.beginFieldToken(token)
	b.data = strconv.AppendUint(b.data, value, 10)
}

func (b *jsonLineBuilder) intField(token string, value int64) {
	b.beginFieldToken(token)
	b.data = strconv.AppendInt(b.data, value, 10)
}

func (b *jsonLineBuilder) boolField(token string, value, omit bool) {
	if omit && !value {
		return
	}
	b.beginFieldToken(token)
	if value {
		b.data = append(b.data, "true"...)
		return
	}
	b.data = append(b.data, "false"...)
}

func (b *jsonLineBuilder) endObject() {
	b.data = append(b.data, '}')
}

func (b *jsonLineBuilder) endLine() []byte {
	b.endObject()
	b.data = append(b.data, '\n')
	return b.data
}

func (b *jsonLineBuilder) uint64ArrayField(token string, values [6]uint64) {
	if values == ([6]uint64{}) {
		b.zeroUint64ArrayField(token)
		return
	}
	b.beginFieldToken(token)
	b.data = append(b.data, '[')
	for index, value := range values {
		if index > 0 {
			b.data = append(b.data, ',')
		}
		b.data = strconv.AppendUint(b.data, value, 10)
	}
	b.data = append(b.data, ']')
}

func (b *jsonLineBuilder) zeroUint64ArrayField(token string) {
	b.beginFieldToken(token)
	b.data = append(b.data, "[0,0,0,0,0,0]"...)
}

func (b *jsonLineBuilder) stringArrayField(token string, values []string) {
	if len(values) == 0 {
		return
	}
	b.beginFieldToken(token)
	b.data = appendJSONStringArray(b.data, values)
}

func (b *jsonLineBuilder) payloadSectionsField(token string, values []jsonPayloadSection) {
	if len(values) == 0 {
		return
	}
	b.beginFieldToken(token)
	b.data = appendJSONPayloadSections(b.data, values)
}

func appendJSONSyscallEvent(dst []byte, event *jsonSyscallEvent) []byte {
	if event == nil {
		return append(dst, "null\n"...)
	}
	builder := jsonLineBuilder{data: dst}
	builder.beginObject()
	builder.stringField(jsonFieldType, event.Type, false)
	builder.uintField(jsonFieldEventVersion, uint64(event.EventVersion), true)
	builder.stringField(jsonFieldEventType, event.EventType, false)
	builder.uintField(jsonFieldEventTypeID, uint64(event.EventTypeID), true)
	builder.uintField(jsonFieldEventFlags, uint64(event.EventFlags), true)
	builder.uintField(jsonFieldPID, uint64(event.Pid), false)
	builder.uintField(jsonFieldTID, uint64(event.Tid), false)
	builder.uintField(jsonFieldSysID, uint64(event.SysID), false)
	builder.stringField(jsonFieldSyscall, event.Syscall, false)
	builder.uint64ArrayField(jsonFieldArgs, event.Args)
	builder.stringArrayField(jsonFieldArgText, event.ArgText)
	builder.intField(jsonFieldRet, event.Ret)
	builder.returnTextField(event)
	builder.boolField(jsonFieldFailed, event.Failed, false)
	builder.intFieldIfNonZero(jsonFieldErrno, int64(event.Errno))
	builder.uintField(jsonFieldDurationNS, event.DurationNS, false)
	builder.uintField(jsonFieldEnterTimeNS, event.EnterTimeNS, false)
	builder.intField(jsonFieldStackID, int64(event.StackID))
	builder.payloadSectionsField(jsonFieldPayloadSections, event.PayloadSections)
	builder.intField(jsonFieldProbeRetEnter, int64(event.ProbeRetEnter))
	builder.intField(jsonFieldProbeRetExit, int64(event.ProbeRetExit))
	builder.boolField(jsonFieldPairedEnter, event.PairedEnter, true)
	return builder.endLine()
}

func (b *jsonLineBuilder) intFieldIfNonZero(token string, value int64) {
	if value == 0 {
		return
	}
	b.intField(token, value)
}

func (b *jsonLineBuilder) returnTextField(event *jsonSyscallEvent) {
	if event.ReturnText != "" {
		b.stringField(jsonFieldReturnText, event.ReturnText, false)
		return
	}
	if !event.hasReturnText {
		return
	}
	b.beginFieldToken(jsonFieldReturnText)
	b.data = appendJSONSyscallReturn(
		b.data,
		event.returnTextName,
		event.returnTextRet,
		event.returnTextRes,
		event.returnTextCtx,
	)
}

func appendJSONSyscallReturn(
	dst []byte,
	syscallName string,
	ret int64,
	res handler.Result,
	ctx *handler.Context,
) []byte {
	if canAppendPlainSyscallReturn(syscallName, ret, res, ctx) {
		dst = append(dst, '"')
		dst = strconv.AppendInt(dst, ret, 10)
		return append(dst, '"')
	}
	return appendJSONString(dst, formatSyscallRet(syscallName, ret, res, ctx))
}

func canAppendPlainSyscallReturn(
	syscallName string,
	ret int64,
	res handler.Result,
	ctx *handler.Context,
) bool {
	if ret < 0 || res.ReturnDesc != "" || res.ShowEmptyReturnDesc {
		return false
	}
	if ctx != nil && ctx.Opts != nil && ctx.Opts.ShowPathsValue() &&
		(isFdReturnSyscall(syscallName) ||
			(isFcntlFDStateSyscall(syscallName) && isFcntlFDStateCommand(ctx.Args))) {
		return false
	}
	switch syscallName {
	case "exit", "exit_group", "fcntl", "fcntl64", "umask", "brk", "mmap", "mremap", "adjtimex", "clock_adjtime":
		return false
	default:
		return true
	}
}

func appendJSONStringArray(dst []byte, values []string) []byte {
	dst = append(dst, '[')
	for index, value := range values {
		if index > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, value)
	}
	return append(dst, ']')
}

func appendJSONPayloadSections(dst []byte, values []jsonPayloadSection) []byte {
	dst = append(dst, '[')
	for index, value := range values {
		if index > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONPayloadSection(dst, value)
	}
	return append(dst, ']')
}

func appendJSONPayloadSection(dst []byte, value jsonPayloadSection) []byte {
	builder := jsonLineBuilder{data: dst}
	builder.beginObject()
	builder.stringField(jsonFieldKind, value.Kind, false)
	builder.stringField(jsonFieldDirection, value.Direction, false)
	builder.intField(jsonFieldArgIndex, int64(value.ArgIndex))
	builder.uintField(jsonFieldUserPtr, value.UserPtr, true)
	builder.uintField(jsonFieldUserLen, uint64(value.UserLen), true)
	builder.uintField(jsonFieldCopiedLen, uint64(value.CopiedLen), false)
	builder.intField(jsonFieldProbeRet, int64(value.ProbeRet))
	builder.base64Field(jsonFieldDataBase64, value.DataBase64, value.rawData)
	builder.endObject()
	return builder.data
}

func (b *jsonLineBuilder) base64Field(token, encoded string, raw []byte) {
	if len(raw) == 0 && encoded == "" {
		return
	}
	b.beginFieldToken(token)
	b.data = append(b.data, '"')
	if raw != nil {
		b.data = base64.StdEncoding.AppendEncode(b.data, raw)
	} else {
		b.data = append(b.data, encoded...)
	}
	b.data = append(b.data, '"')
}

func appendJSONString(dst []byte, value string) []byte {
	dst = append(dst, '"')
	for index := 0; index < len(value); {
		if value[index] < utf8.RuneSelf {
			dst = appendJSONASCII(dst, value[index])
			index++
			continue
		}
		runeValue, size := utf8.DecodeRuneInString(value[index:])
		if runeValue == utf8.RuneError && size == 1 {
			dst = appendUnicodeEscape(dst, utf8.RuneError)
			index++
			continue
		}
		if runeValue == '\u2028' || runeValue == '\u2029' {
			dst = appendUnicodeEscape(dst, runeValue)
		} else {
			dst = append(dst, value[index:index+size]...)
		}
		index += size
	}
	return append(dst, '"')
}

func appendJSONASCII(dst []byte, value byte) []byte {
	switch value {
	case '"', '\\':
		return append(dst, '\\', value)
	case '\b':
		return append(dst, '\\', 'b')
	case '\f':
		return append(dst, '\\', 'f')
	case '\n':
		return append(dst, '\\', 'n')
	case '\r':
		return append(dst, '\\', 'r')
	case '\t':
		return append(dst, '\\', 't')
	case '<':
		return appendUnicodeEscape(dst, '<')
	case '>':
		return appendUnicodeEscape(dst, '>')
	case '&':
		return appendUnicodeEscape(dst, '&')
	default:
		if value < 0x20 {
			return appendUnicodeEscape(dst, rune(value))
		}
		return append(dst, value)
	}
}

func appendUnicodeEscape(dst []byte, value rune) []byte {
	const hex = "0123456789abcdef"
	return append(dst, '\\', 'u',
		hex[(value>>12)&0xf],
		hex[(value>>8)&0xf],
		hex[(value>>4)&0xf],
		hex[value&0xf])
}
