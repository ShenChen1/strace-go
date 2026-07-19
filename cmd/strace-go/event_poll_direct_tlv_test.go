package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesPollDirectTLVSections(t *testing.T) {
	tests := []struct {
		name        string
		args        [6]uint64
		wantTimeout bool
	}{
		{name: "poll", args: [6]uint64{0x2000, 2, 1000}},
		{name: "ppoll", args: [6]uint64{0x2000, 2, 0x3000, 0x4000, 8}, wantTimeout: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := miscStructTLVSession(tt.name)
			enterFds := append(pollDirectTestPollfdData(4, 1, 0), pollDirectTestPollfdData(5, 4, 0)...)
			enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindStruct,
				arg:     0,
				userPtr: tt.args[0],
				userLen: uint32(len(enterFds)),
				data:    enterFds,
			})
			timeout := pollDirectTestTimespecData(9, 10)
			if tt.wantTimeout {
				enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
					kind:    payloadTLVKindStruct,
					arg:     2,
					userPtr: tt.args[2],
					userLen: uint32(len(timeout)),
					data:    timeout,
				})...)
				sigmask := pollDirectTestSigsetData((1 << 11) | (1 << 16))
				enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
					kind:    payloadTLVKindStruct,
					arg:     3,
					userPtr: tt.args[3],
					userLen: uint32(len(sigmask)),
					data:    sigmask,
				})...)
			}
			enterRaw := miscStructTLVEvent(t, tt.name, bpfEventTypeEnter, tt.args, 0, enterPayload)
			enterRaw.EventFlags |= bpfEventFlagGenericEnter
			session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

			exitFds := append(pollDirectTestPollfdData(4, 0, 1), pollDirectTestPollfdData(5, 0, 4)...)
			exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
				kind:    payloadTLVKindStruct,
				flags:   payloadTLVFlagDirectionOut,
				arg:     0,
				userPtr: tt.args[0],
				userLen: uint32(len(exitFds)),
				data:    exitFds,
			})
			if tt.wantTimeout {
				exitPayload = append(exitPayload, payloadTLVBytes(t, payloadTLVTestSection{
					kind:    payloadTLVKindStruct,
					flags:   payloadTLVFlagDirectionOut,
					arg:     2,
					userPtr: tt.args[2],
					userLen: uint32(len(timeout)),
					data:    timeout,
				})...)
			}
			exitRaw := miscStructTLVEvent(t, tt.name, bpfEventTypeExit, tt.args, 2, exitPayload)
			exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
			ev := newSyscallEventContextFromView(
				session,
				exitUpdate.syscallView,
				101,
				exitUpdate.pendingEnter,
				exitUpdate.payloadSections)

			enterSection, ok := pollDirectSection(ev.handlerContext.PayloadSections, 0, handler.PayloadDirectionIn)
			if !ok || enterSection.Direction != handler.PayloadDirectionIn || !bytes.Equal(enterSection.Data, enterFds) {
				t.Fatalf("%s enter fds section = %+v, %v; want pending enter IN struct TLV", tt.name, enterSection, ok)
			}
			exitSection, ok := pollDirectSection(ev.handlerContext.PayloadSections, 0, handler.PayloadDirectionOut)
			if !ok || exitSection.Direction != handler.PayloadDirectionOut || !bytes.Equal(exitSection.Data, exitFds) {
				t.Fatalf("%s exit fds section = %+v, %v; want direct OUT struct TLV", tt.name, exitSection, ok)
			}
			if tt.wantTimeout {
				timeoutSection, ok := pollDirectSection(ev.handlerContext.PayloadSections, 2, handler.PayloadDirectionIn)
				if !ok || timeoutSection.Direction != handler.PayloadDirectionIn || !bytes.Equal(timeoutSection.Data, timeout) {
					t.Fatalf("ppoll timeout section = %+v, %v; want pending enter IN struct TLV", timeoutSection, ok)
				}
				timeoutOutSection, ok := pollDirectSection(ev.handlerContext.PayloadSections, 2, handler.PayloadDirectionOut)
				if !ok || timeoutOutSection.Direction != handler.PayloadDirectionOut || !bytes.Equal(timeoutOutSection.Data, timeout) {
					t.Fatalf("ppoll timeout out section = %+v, %v; want direct OUT struct TLV", timeoutOutSection, ok)
				}
				sigmaskSection, ok := pollDirectSection(ev.handlerContext.PayloadSections, 3, handler.PayloadDirectionIn)
				if !ok || sigmaskSection.Direction != handler.PayloadDirectionIn || !bytes.Equal(sigmaskSection.Data, pollDirectTestSigsetData((1<<11)|(1<<16))) {
					t.Fatalf("ppoll sigmask section = %+v, %v; want pending enter IN struct TLV", sigmaskSection, ok)
				}
			}
		})
	}
}

func pollDirectSection(
	sections []handler.PayloadSection,
	argIndex int,
	direction handler.PayloadDirection,
) (handler.PayloadSection, bool) {
	for _, section := range sections {
		if section.Kind == handler.PayloadKindStruct &&
			section.ArgIndex == argIndex &&
			section.Direction == direction {
			return section, true
		}
	}
	return handler.PayloadSection{}, false
}

func pollDirectTestPollfdData(fd int32, events uint16, revents uint16) []byte {
	buf := make([]byte, pollPayloadFdSize)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(fd))
	binary.LittleEndian.PutUint16(buf[4:6], events)
	binary.LittleEndian.PutUint16(buf[6:8], revents)
	return buf
}

func pollDirectTestTimespecData(sec int64, nsec uint64) []byte {
	buf := make([]byte, timespecPayloadStructSize)
	binary.LittleEndian.PutUint64(buf[0:8], uint64(sec))
	binary.LittleEndian.PutUint64(buf[8:16], nsec)
	return buf
}

func pollDirectTestSigsetData(mask uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, mask)
	return buf
}
