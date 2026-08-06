package handler

import (
	"encoding/binary"
	"strconv"
	"testing"
)

func TestSendmsgHandlerFormatsTimestampControlMessages(t *testing.T) {
	tests := []struct {
		name        string
		cmsgType    uint32
		payload     []byte
		wantControl string
	}{
		{
			name:        "timeval old",
			cmsgType:    soTimestampOld,
			payload:     cmsgTimevalBytes(123456789, 987654),
			wantControl: `[{cmsg_len=32, cmsg_level=SOL_SOCKET, cmsg_type=SO_TIMESTAMP_OLD, cmsg_data={tv_sec=123456789, tv_usec=987654}}]`,
		},
		{
			name:        "timespec ns new",
			cmsgType:    soTimestampNSNew,
			payload:     cmsgTimespecBytes(11, 12),
			wantControl: `[{cmsg_len=32, cmsg_level=SOL_SOCKET, cmsg_type=SO_TIMESTAMPNS_NEW, cmsg_data={tv_sec=11, tv_nsec=12}}]`,
		},
		{
			name:     "timestamping old",
			cmsgType: soTimestampingOld,
			payload: cmsgTimespecArrayBytes(
				[2]uint64{123456789, 987654321},
				[2]uint64{123456790, 987654320},
				[2]uint64{123456791, 987654319},
			),
			wantControl: `[{cmsg_len=64, cmsg_level=SOL_SOCKET, cmsg_type=SO_TIMESTAMPING_OLD, cmsg_data=[{tv_sec=123456789, tv_nsec=987654321}, {tv_sec=123456790, tv_nsec=987654320}, {tv_sec=123456791, tv_nsec=987654319}]}]`,
		},
		{
			name:        "short timestamp new",
			cmsgType:    soTimestampNew,
			payload:     cmsgTimevalBytes(1, 2)[:8],
			wantControl: `[{cmsg_len=24, cmsg_level=SOL_SOCKET, cmsg_type=SO_TIMESTAMP_NEW, cmsg_data=???}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := newMsgPolicyContext("sendmsg")
			ctx.Ret = -9
			ctx.Args = [6]uint64{3, 0x1000, 0}
			control := cmsgBytes(solSocket, tt.cmsgType, tt.payload)
			ctx.PayloadSections = []PayloadSection{
				{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
				{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
			}

			res := (&MsgHandler{}).Handle(ctx)

			wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=` + tt.wantControl + `, msg_controllen=` + cmsgControlLenString(len(control)) + `, msg_flags=0}`
			assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
		})
	}
}

func cmsgTimevalBytes(sec int64, usec uint64) []byte {
	return cmsgTwoWordTimeBytes(sec, usec)
}

func cmsgTimespecBytes(sec uint64, nsec uint64) []byte {
	return cmsgTwoWordTimeBytes(int64(sec), nsec)
}

func cmsgTwoWordTimeBytes(sec int64, subsec uint64) []byte {
	data := make([]byte, cmsgTimeSize)
	binary.LittleEndian.PutUint64(data[0:8], uint64(sec))
	binary.LittleEndian.PutUint64(data[8:16], subsec)
	return data
}

func cmsgTimespecArrayBytes(values ...[2]uint64) []byte {
	data := make([]byte, 0, len(values)*cmsgTimeSize)
	for _, value := range values {
		data = append(data, cmsgTimespecBytes(value[0], value[1])...)
	}
	return data
}

func cmsgControlLenString(length int) string {
	return strconv.Itoa(length)
}
