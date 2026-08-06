package handler

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestSendmsgHandlerLimitsRightsControlMessageArray(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := cmsgRightsRange(40)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	got := strings.Join(res.ArgParts, ", ")
	wantData := `cmsg_data=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, ...]`
	if !strings.Contains(got, wantData) {
		t.Fatalf("SCM_RIGHTS data = %q, want substring %q", got, wantData)
	}
	if strings.Contains(got, "32, 33") {
		t.Fatalf("SCM_RIGHTS data was not capped: %q", got)
	}
}

func TestSendmsgHandlerFormatsShortControlMessageLength(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := append(cmsgHeaderBytes(1, solSocket, scmRights), make([]byte, cmsgHeaderSize)...)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=1, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS}, ... /* 0x5010 */], msg_controllen=32, msg_flags=0}`
	assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestSendmsgHandlerFormatsPartialRightsPayloadAsHex(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := append(cmsgHeaderBytes(17, solSocket, scmRights), 0xf6)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=17, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data="\xf6"}], msg_controllen=17, msg_flags=0}`
	assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestSendmsgHandlerFormatsIPControlMessages(t *testing.T) {
	tests := []struct {
		name        string
		cmsgType    uint32
		payload     []byte
		wantControl string
	}{
		{
			name:        "pktinfo",
			cmsgType:    ipPktinfo,
			payload:     ipPktinfoBytes(0, [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8}),
			wantControl: `{cmsg_len=28, cmsg_level=SOL_IP, cmsg_type=IP_PKTINFO, cmsg_data={ipi_ifindex=0, ipi_spec_dst=inet_addr("1.2.3.4"), ipi_addr=inet_addr("5.6.7.8")}}`,
		},
		{
			name:        "ttl",
			cmsgType:    ipTTL,
			payload:     cmsgUint32Bytes(0xfacefeed),
			wantControl: `{cmsg_len=20, cmsg_level=SOL_IP, cmsg_type=IP_TTL, cmsg_data=[4207869677]}`,
		},
		{
			name:        "tos",
			cmsgType:    ipTOS,
			payload:     []byte{'A'},
			wantControl: `{cmsg_len=17, cmsg_level=SOL_IP, cmsg_type=IP_TOS, cmsg_data=[0x41]}`,
		},
		{
			name:        "protocol",
			cmsgType:    ipProtocol,
			payload:     cmsgUint32Bytes(255),
			wantControl: `{cmsg_len=20, cmsg_level=SOL_IP, cmsg_type=IP_PROTOCOL, cmsg_data=[IPPROTO_RAW]}`,
		},
		{
			name:        "recv err",
			cmsgType:    ipRecvErr,
			payload:     ipRecvErrBytes(),
			wantControl: `{cmsg_len=48, cmsg_level=SOL_IP, cmsg_type=IP_RECVERR, cmsg_data={ee_errno=3735928559, ee_origin=2, ee_type=3, ee_code=4, ee_info=4207869677, ee_data=3134983661, offender={sa_family=AF_INET, sin_port=htons(12345), sin_addr=inet_addr("127.0.0.1")}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := handleIPControlMessage(t, tt.cmsgType, tt.payload)
			wantMsg := fmt.Sprintf(`{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[%s], msg_controllen=%d, msg_flags=0}`,
				tt.wantControl, alignCmsgLen(cmsgHeaderSize+len(tt.payload)))
			assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
		})
	}
}

func TestSendmsgHandlerLimitsIPOptionsControlMessageArray(t *testing.T) {
	payload := make([]byte, 40)
	for i := range payload {
		payload[i] = byte('A' + i)
	}

	res := handleIPControlMessage(t, ipRetOpts, payload)

	got := strings.Join(res.ArgParts, ", ")
	wantData := `cmsg_type=IP_RETOPTS, cmsg_data=[0x41, 0x42, 0x43`
	if !strings.Contains(got, wantData) || !strings.Contains(got, "0x60, ...]") {
		t.Fatalf("IP_RETOPTS data was not capped as expected: %q", got)
	}
	if strings.Contains(got, "0x61") {
		t.Fatalf("IP_RETOPTS data included bytes beyond display cap: %q", got)
	}
}

func cmsgRightsRange(count int) []byte {
	data := cmsgBytes(solSocket, scmRights, make([]byte, count*4))
	for i := 0; i < count; i++ {
		binary.LittleEndian.PutUint32(data[cmsgHeaderSize+i*4:cmsgHeaderSize+i*4+4], uint32(i))
	}
	return data
}

func cmsgHeaderBytes(length uint64, level uint32, cmsgType uint32) []byte {
	data := make([]byte, cmsgHeaderSize)
	binary.LittleEndian.PutUint64(data[0:8], length)
	binary.LittleEndian.PutUint32(data[8:12], level)
	binary.LittleEndian.PutUint32(data[12:16], cmsgType)
	return data
}

func handleIPControlMessage(t *testing.T, cmsgType uint32, payload []byte) Result {
	t.Helper()
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := cmsgBytes(solIP, cmsgType, payload)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}
	return (&MsgHandler{}).Handle(ctx)
}

func ipPktinfoBytes(ifindex uint32, specDst [4]byte, addr [4]byte) []byte {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint32(data[0:4], ifindex)
	copy(data[4:8], specDst[:])
	copy(data[8:12], addr[:])
	return data
}

func cmsgUint32Bytes(value uint32) []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, value)
	return data
}

func ipRecvErrBytes() []byte {
	data := make([]byte, 32)
	binary.LittleEndian.PutUint32(data[0:4], 0xdeadbeef)
	data[4] = 2
	data[5] = 3
	data[6] = 4
	binary.LittleEndian.PutUint32(data[8:12], 0xfacefeed)
	binary.LittleEndian.PutUint32(data[12:16], 0xbadc0ded)
	binary.LittleEndian.PutUint16(data[16:18], 2)
	binary.BigEndian.PutUint16(data[18:20], 12345)
	copy(data[20:24], []byte{127, 0, 0, 1})
	return data
}
