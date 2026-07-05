package handler

import (
	"encoding/binary"
	"errors"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

type networkPolicyMemoryReader struct {
	data  map[uint64][]byte
	reads int
}

func (r *networkPolicyMemoryReader) Read(_ int, addr uint64, size int) ([]byte, error) {
	r.reads++
	data, ok := r.data[addr]
	if !ok {
		return nil, errors.New("unreadable address")
	}
	if size >= 0 && size < len(data) {
		data = data[:size]
	}
	return append([]byte(nil), data...), nil
}

func (r *networkPolicyMemoryReader) ReadRobust(pid int, addr uint64, size int, _ bool) ([]byte, error) {
	return r.Read(pid, addr, size)
}

func newNetworkPolicyContext(reader *networkPolicyMemoryReader, name string) *Context {
	return &Context{
		Pid:           1234,
		Tid:           1234,
		TargetPid:     1234,
		ScMeta:        meta.Syscall{Name: name},
		ProbeRetEnter: -1,
		ProbeRetExit:  -1,
		Decoder:       event.NewDecoder(),
		Opts:          &cli.Options{StringLimit: 32},
		FdMap:         map[string]string{},
	}
}

func uint32Bytes(v uint32) []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, v)
	return data
}

func sockaddrInet(port uint16, ip [4]byte) []byte {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint16(data[0:2], 2)
	binary.BigEndian.PutUint16(data[2:4], port)
	copy(data[4:8], ip[:])
	return data
}

func TestNetworkAddrLenIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x1000: uint32Bytes(16)}}
	ctx := newNetworkPolicyContext(reader, "recvfrom")
	ctx.Ret = 3
	ctx.ProbeRetEnter = 0
	ctx.ProbeRetExit = 0

	got, ok := (&NetworkHandler{}).formatNetworkAddrLen(ctx, "addr_len", 0x1000)
	if !ok || got != "0x1000" {
		t.Fatalf("formatNetworkAddrLen() = %q, %v; want pointer fallback", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkAddrLenFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x1000: uint32Bytes(16)}}
	ctx := newNetworkPolicyContext(reader, "recvfrom")
	ctx.Ret = 3

	got, ok := (&NetworkHandler{}).formatNetworkAddrLen(ctx, "addr_len", 0x1000)
	if !ok || got != "0x1000" {
		t.Fatalf("formatNetworkAddrLen() = %q, %v; want pointer fallback", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkBufferIgnoresProbeSuccessWithoutPayloadSectionOnSendto(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x2000: []byte("abc")}}
	ctx := newNetworkPolicyContext(reader, "sendto")
	ctx.Args = [6]uint64{3, 0x2000, 3}
	ctx.ProbeRetEnter = 0

	got, ok := (&NetworkHandler{}).formatNetworkBuffer(ctx, 1, 0x2000)
	if !ok || got != "0x2000" {
		t.Fatalf("formatNetworkBuffer() = %q, %v; want pointer fallback", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkBufferUsesSendtoPayloadBytesSection(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x2000: []byte("abc")}}
	ctx := newNetworkPolicyContext(reader, "sendto")
	ctx.Args = [6]uint64{3, 0x2000, 3}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: []byte("abc")},
	}

	got, ok := (&NetworkHandler{}).formatNetworkBuffer(ctx, 1, 0x2000)
	if !ok || got != `"abc"` {
		t.Fatalf("formatNetworkBuffer() = %q, %v; want payload buffer", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkBufferIgnoresProbeSuccessWithoutPayloadSectionOnRecvfrom(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x2000: []byte("abc")}}
	ctx := newNetworkPolicyContext(reader, "recvfrom")
	ctx.Args = [6]uint64{3, 0x2000, 5}
	ctx.Ret = 3
	ctx.ProbeRetExit = 0

	got, ok := (&NetworkHandler{}).formatNetworkBuffer(ctx, 1, 0x2000)
	if !ok || got != "0x2000" {
		t.Fatalf("formatNetworkBuffer() = %q, %v; want pointer fallback", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkBufferUsesRecvfromPayloadBytesSection(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x2000: []byte("abc")}}
	ctx := newNetworkPolicyContext(reader, "recvfrom")
	ctx.Args = [6]uint64{3, 0x2000, 5}
	ctx.Ret = 3
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: []byte("abc")},
	}

	got, ok := (&NetworkHandler{}).formatNetworkBuffer(ctx, 1, 0x2000)
	if !ok || got != `"abc"` {
		t.Fatalf("formatNetworkBuffer() = %q, %v; want payload buffer", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkZeroLengthBufferDoesNotRead(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x2000: []byte("abc")}}
	ctx := newNetworkPolicyContext(reader, "sendto")
	ctx.Args = [6]uint64{3, 0x2000, 0}

	got, ok := (&NetworkHandler{}).formatNetworkBuffer(ctx, 1, 0x2000)
	if !ok || got != `""` {
		t.Fatalf("formatNetworkBuffer() = %q, %v; want empty buffer", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkNetlinkBufferFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x3000: make([]byte, 16)}}
	ctx := newNetworkPolicyContext(reader, "sendto")
	ctx.Args = [6]uint64{3, 0x3000, 16}

	got := (&NetworkHandler{}).formatNetlinkBuf(ctx, 0x3000)
	if got != "0x3000" {
		t.Fatalf("formatNetlinkBuf() = %q, want pointer fallback", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkSockaddrFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x4000: sockaddrInet(80, [4]byte{127, 0, 0, 1})}}
	ctx := newNetworkPolicyContext(reader, "connect")
	ctx.Args = [6]uint64{3, 0x4000, 16}

	got, ok := (&NetworkHandler{}).formatSockaddr(ctx, 1, "uservaddr", "struct sockaddr *", 0x4000)
	if !ok || got != "0x4000" {
		t.Fatalf("formatSockaddr() = %q, %v; want pointer fallback", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkSockaddrIgnoresProbeSuccessWithoutPayloadSectionOnConnect(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x4000: sockaddrInet(80, [4]byte{127, 0, 0, 1})}}
	ctx := newNetworkPolicyContext(reader, "connect")
	ctx.Args = [6]uint64{3, 0x4000, 16}
	ctx.ProbeRetEnter = 0

	got, ok := (&NetworkHandler{}).formatSockaddr(ctx, 1, "uservaddr", "struct sockaddr *", 0x4000)
	if !ok || got != "0x4000" {
		t.Fatalf("formatSockaddr() = %q, %v; want pointer fallback", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkSockaddrUsesConnectPayloadStructSection(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x4000: sockaddrInet(80, [4]byte{127, 0, 0, 1})}}
	ctx := newNetworkPolicyContext(reader, "connect")
	ctx.Args = [6]uint64{3, 0x4000, 16}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: sockaddrInet(80, [4]byte{127, 0, 0, 1})},
	}

	got, ok := (&NetworkHandler{}).formatSockaddr(ctx, 1, "uservaddr", "struct sockaddr *", 0x4000)
	want := `{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}`
	if !ok || got != want {
		t.Fatalf("formatSockaddr() = %q, %v; want %q", got, ok, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkSockaddrIgnoresProbeSuccessWithoutPayloadSectionOnSendto(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x4000: sockaddrInet(80, [4]byte{127, 0, 0, 1})}}
	ctx := newNetworkPolicyContext(reader, "sendto")
	ctx.Args = [6]uint64{3, 0x2000, 3, 0, 0x4000, 16}
	ctx.ProbeRetEnter = 0

	got, ok := (&NetworkHandler{}).formatSockaddr(ctx, 4, "addr", "struct sockaddr *", 0x4000)
	if !ok || got != "0x4000" {
		t.Fatalf("formatSockaddr() = %q, %v; want pointer fallback", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkSockaddrUsesSendtoPayloadStructSection(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x4000: sockaddrInet(80, [4]byte{127, 0, 0, 1})}}
	ctx := newNetworkPolicyContext(reader, "sendto")
	ctx.Args = [6]uint64{3, 0x2000, 3, 0, 0x4000, 16}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 4, ProbeRet: 0, Data: sockaddrInet(80, [4]byte{127, 0, 0, 1})},
	}

	got, ok := (&NetworkHandler{}).formatSockaddr(ctx, 4, "addr", "struct sockaddr *", 0x4000)
	want := `{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}`
	if !ok || got != want {
		t.Fatalf("formatSockaddr() = %q, %v; want %q", got, ok, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkSockaddrUsesRecvfromPayloadStructSection(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x4000: sockaddrInet(80, [4]byte{127, 0, 0, 1})}}
	ctx := newNetworkPolicyContext(reader, "recvfrom")
	ctx.Args = [6]uint64{3, 0x2000, 3, 0, 0x4000, 0x5000}
	ctx.Ret = 3
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 5, ProbeRet: 0, Data: uint32Bytes(16)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 5, ProbeRet: 0, Data: uint32Bytes(16)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 4, ProbeRet: 0, Data: sockaddrInet(80, [4]byte{127, 0, 0, 1})},
	}

	got, ok := (&NetworkHandler{}).formatSockaddr(ctx, 4, "addr", "struct sockaddr *", 0x4000)
	want := `{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}`
	if !ok || got != want {
		t.Fatalf("formatSockaddr() = %q, %v; want %q", got, ok, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkSockaddrUsesAcceptPayloadStructSection(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x4000: sockaddrInet(80, [4]byte{127, 0, 0, 1})}}
	ctx := newNetworkPolicyContext(reader, "accept")
	ctx.Args = [6]uint64{3, 0x4000, 0x5000}
	ctx.Ret = 4
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 2, ProbeRet: 0, Data: uint32Bytes(16)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 2, ProbeRet: 0, Data: uint32Bytes(16)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: sockaddrInet(80, [4]byte{127, 0, 0, 1})},
	}

	got, ok := (&NetworkHandler{}).formatSockaddr(ctx, 1, "upeer_sockaddr", "struct sockaddr *", 0x4000)
	want := `{sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("127.0.0.1")}`
	if !ok || got != want {
		t.Fatalf("formatSockaddr() = %q, %v; want %q", got, ok, want)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkGetSockaddrLenFallsBackToZeroWithoutSnapshot(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x5000: uint32Bytes(16)}}
	ctx := newNetworkPolicyContext(reader, "recvfrom")
	ctx.Args = [6]uint64{3, 0, 0, 0, 0, 0x5000}

	got := (&NetworkHandler{}).getSockaddrLen(ctx)
	if got != 0 {
		t.Fatalf("getSockaddrLen() = %d, want 0", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkGetSockaddrLenIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x5000: uint32Bytes(16)}}
	ctx := newNetworkPolicyContext(reader, "recvfrom")
	ctx.Args = [6]uint64{3, 0, 0, 0, 0, 0x5000}
	ctx.ProbeRetExit = 0

	got := (&NetworkHandler{}).getSockaddrLen(ctx)
	if got != 0 {
		t.Fatalf("getSockaddrLen() = %d, want 0", got)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkAddrLenUsesPayloadBytesSections(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x1000: uint32Bytes(16)}}
	ctx := newNetworkPolicyContext(reader, "recvfrom")
	ctx.Ret = 3
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: 5, ProbeRet: 0, Data: uint32Bytes(16)},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 5, ProbeRet: 0, Data: uint32Bytes(8)},
	}

	got, ok := (&NetworkHandler{}).formatNetworkAddrLen(ctx, "addr_len", 0x1000)
	if !ok || got != "[16 => 8]" {
		t.Fatalf("formatNetworkAddrLen() = %q, %v; want payload len transition", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkGetsockoptLenFallsBackToPointerWithoutSnapshot(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x6000: uint32Bytes(4)}}
	ctx := newNetworkPolicyContext(reader, "getsockopt")
	ctx.Ret = 0

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 4, "optlen", 0x6000)
	if !ok || got != "0x6000" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want pointer fallback", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkGetsockoptLenIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x6000: uint32Bytes(4)}}
	ctx := newNetworkPolicyContext(reader, "getsockopt")
	ctx.Ret = 0
	ctx.ProbeRetExit = 0

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 4, "optlen", 0x6000)
	if !ok || got != "0x6000" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want pointer fallback", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestNetworkGetsockoptLenUsesPayloadBytesSection(t *testing.T) {
	reader := &networkPolicyMemoryReader{data: map[uint64][]byte{0x6000: uint32Bytes(4)}}
	ctx := newNetworkPolicyContext(reader, "getsockopt")
	ctx.Ret = 0
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: 4, ProbeRet: 0, Data: uint32Bytes(4)},
	}

	got, ok := (&NetworkHandler{}).formatSockoptValAndLen(ctx, 4, "optlen", 0x6000)
	if !ok || got != "[4]" {
		t.Fatalf("formatSockoptValAndLen() = %q, %v; want payload optlen", got, ok)
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
