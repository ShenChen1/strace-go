package main

import (
	"encoding/base64"
	"strconv"
	"unicode/utf8"

	"strace-go/pkg/handler"
)

type jsonLineBuilder struct {
	data  []byte
	first bool
}

func (b *jsonLineBuilder) beginObject() {
	b.data = append(b.data, '{')
	b.first = true
}

func (b *jsonLineBuilder) beginField(name string) {
	if !b.first {
		b.data = append(b.data, ',')
	}
	b.first = false
	b.data = append(b.data, '"')
	b.data = append(b.data, name...)
	b.data = append(b.data, '"', ':')
}

func (b *jsonLineBuilder) stringField(name, value string, omit bool) {
	if omit && value == "" {
		return
	}
	b.beginField(name)
	b.data = appendJSONString(b.data, value)
}

func (b *jsonLineBuilder) uintField(name string, value uint64, omit bool) {
	if omit && value == 0 {
		return
	}
	b.beginField(name)
	b.data = strconv.AppendUint(b.data, value, 10)
}

func (b *jsonLineBuilder) intField(name string, value int64) {
	b.beginField(name)
	b.data = strconv.AppendInt(b.data, value, 10)
}

func (b *jsonLineBuilder) boolField(name string, value, omit bool) {
	if omit && !value {
		return
	}
	b.beginField(name)
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

func (b *jsonLineBuilder) uint64ArrayField(name string, values [6]uint64) {
	b.beginField(name)
	b.data = append(b.data, '[')
	for index, value := range values {
		if index > 0 {
			b.data = append(b.data, ',')
		}
		b.data = strconv.AppendUint(b.data, value, 10)
	}
	b.data = append(b.data, ']')
}

func (b *jsonLineBuilder) stringArrayField(name string, values []string) {
	if len(values) == 0 {
		return
	}
	b.beginField(name)
	b.data = appendJSONStringArray(b.data, values)
}

func (b *jsonLineBuilder) payloadSectionsField(name string, values []jsonPayloadSection) {
	if len(values) == 0 {
		return
	}
	b.beginField(name)
	b.data = appendJSONPayloadSections(b.data, values)
}

func appendJSONSyscallEvent(dst []byte, event *jsonSyscallEvent) []byte {
	if event == nil {
		return append(dst, "null\n"...)
	}
	builder := jsonLineBuilder{data: dst}
	builder.beginObject()
	builder.stringField("type", event.Type, false)
	builder.uintField("event_version", uint64(event.EventVersion), true)
	builder.stringField("event_type", event.EventType, false)
	builder.uintField("event_type_id", uint64(event.EventTypeID), true)
	builder.uintField("event_flags", uint64(event.EventFlags), true)
	builder.uintField("pid", uint64(event.Pid), false)
	builder.uintField("tid", uint64(event.Tid), false)
	builder.uintField("sys_id", uint64(event.SysID), false)
	builder.stringField("syscall", event.Syscall, false)
	builder.uint64ArrayField("args", event.Args)
	builder.stringArrayField("arg_text", event.ArgText)
	builder.intField("ret", event.Ret)
	builder.returnTextField(event)
	builder.boolField("failed", event.Failed, false)
	builder.intFieldIfNonZero("errno", int64(event.Errno))
	builder.uintField("duration_ns", event.DurationNS, false)
	builder.uintField("enter_time_ns", event.EnterTimeNS, false)
	builder.intField("stack_id", int64(event.StackID))
	builder.payloadSectionsField("payload_sections", event.PayloadSections)
	builder.intField("probe_ret_enter", int64(event.ProbeRetEnter))
	builder.intField("probe_ret_exit", int64(event.ProbeRetExit))
	builder.boolField("paired_enter", event.PairedEnter, true)
	return builder.endLine()
}

func (b *jsonLineBuilder) intFieldIfNonZero(name string, value int64) {
	if value == 0 {
		return
	}
	b.intField(name, value)
}

func (b *jsonLineBuilder) returnTextField(event *jsonSyscallEvent) {
	if event.ReturnText != "" {
		b.stringField("return_text", event.ReturnText, false)
		return
	}
	if !event.hasReturnText {
		return
	}
	b.beginField("return_text")
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
	builder.stringField("kind", value.Kind, false)
	builder.stringField("direction", value.Direction, false)
	builder.intField("arg_index", int64(value.ArgIndex))
	builder.uintField("user_ptr", value.UserPtr, true)
	builder.uintField("user_len", uint64(value.UserLen), true)
	builder.uintField("copied_len", uint64(value.CopiedLen), false)
	builder.intField("probe_ret", int64(value.ProbeRet))
	builder.base64Field("data_base64", value.DataBase64, value.rawData)
	builder.endObject()
	return builder.data
}

func (b *jsonLineBuilder) base64Field(name, encoded string, raw []byte) {
	if len(raw) == 0 && encoded == "" {
		return
	}
	b.beginField(name)
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
