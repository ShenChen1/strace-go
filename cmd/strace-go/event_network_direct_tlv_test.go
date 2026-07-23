package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"strace-go/pkg/handler"
)

func TestSyscallEventContextMergesRecvfromDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("recvfrom")
	args := [6]uint64{3, 0x2000, 5, 0, 0x4000, 0x5000}
	enterLen := networkDirectSocklen(16)
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     5,
		userPtr: args[5],
		userLen: socklenPayloadSize,
		data:    enterLen,
	})
	enterRaw := miscStructTLVEvent(t, "recvfrom", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	recvData := []byte("abc")
	sockaddrData := jsonSockaddrInet(80, [4]byte{127, 0, 0, 1})
	exitLen := networkDirectSocklen(16)
	exitPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   payloadTLVFlagDirectionOut,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(recvData)),
		data:    recvData,
	})
	exitPayload = append(exitPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		flags:   payloadTLVFlagDirectionOut,
		arg:     4,
		userPtr: args[4],
		userLen: uint32(len(sockaddrData)),
		data:    sockaddrData,
	})...)
	exitPayload = append(exitPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		flags:   payloadTLVFlagDirectionOut,
		arg:     5,
		userPtr: args[5],
		userLen: socklenPayloadSize,
		data:    exitLen,
	})...)
	exitRaw := miscStructTLVEvent(t, "recvfrom", bpfEventTypeExit, args, int64(len(recvData)), exitPayload)

	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	requireNetworkDirectBytes(t, ev, 5, handler.PayloadDirectionIn, enterLen)
	requireNetworkDirectBytes(t, ev, 1, handler.PayloadDirectionOut, recvData)
	requireNetworkDirectStruct(t, ev, 4, handler.PayloadDirectionOut, sockaddrData)
	requireNetworkDirectBytes(t, ev, 5, handler.PayloadDirectionOut, exitLen)
}

func TestSyscallEventContextMergesSendtoDirectTLVSections(t *testing.T) {
	session := miscStructTLVSession("sendto")
	args := [6]uint64{3, 0x2000, 3, 0, 0x4000, 16}
	sendData := []byte("abc")
	sockaddrData := jsonSockaddrInet(80, [4]byte{127, 0, 0, 1})
	enterPayload := payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindBytes,
		arg:     1,
		userPtr: args[1],
		userLen: uint32(len(sendData)),
		data:    sendData,
	})
	enterPayload = append(enterPayload, payloadTLVBytes(t, payloadTLVTestSection{
		kind:    payloadTLVKindStruct,
		arg:     4,
		userPtr: args[4],
		userLen: uint32(len(sockaddrData)),
		data:    sockaddrData,
	})...)
	enterRaw := miscStructTLVEvent(t, "sendto", bpfEventTypeEnter, args, 0, enterPayload)
	enterRaw.EventFlags |= bpfEventFlagGenericEnter
	session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(enterRaw))

	exitRaw := miscStructTLVEvent(t, "sendto", bpfEventTypeExit, args, int64(len(sendData)), nil)
	exitUpdate := session.traceState().handleEnvelope(newTraceEventEnvelopeFromBPF(exitRaw))
	ev := newSyscallEventContextFromView(
		session,
		exitUpdate.syscallView,
		101,
		exitUpdate.pendingEnter,
		exitUpdate.payloadSections)

	requireNetworkDirectBytes(t, ev, 1, handler.PayloadDirectionIn, sendData)
	requireNetworkDirectStruct(t, ev, 4, handler.PayloadDirectionIn, sockaddrData)
}

func networkDirectSocklen(v uint32) []byte {
	data := make([]byte, socklenPayloadSize)
	binary.LittleEndian.PutUint32(data, v)
	return data
}

func requireNetworkDirectBytes(
	t *testing.T,
	ev syscallEventContext,
	argIndex int,
	direction handler.PayloadDirection,
	want []byte,
) {
	t.Helper()
	got, ok := ev.handlerContext.PayloadBytes(argIndex, direction)
	if !ok || !bytes.Equal(got, want) {
		t.Fatalf("network bytes arg %d %s = %v, %v; want direct TLV bytes", argIndex, direction, got, ok)
	}
}

func requireNetworkDirectStruct(
	t *testing.T,
	ev syscallEventContext,
	argIndex int,
	direction handler.PayloadDirection,
	want []byte,
) {
	t.Helper()
	got, ok := ev.handlerContext.PayloadStruct(argIndex, direction)
	if !ok || !bytes.Equal(got, want) {
		t.Fatalf("network struct arg %d %s = %v, %v; want direct TLV struct", argIndex, direction, got, ok)
	}
}
