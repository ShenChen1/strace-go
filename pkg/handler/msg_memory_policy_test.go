package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func TestSendmsgHandlerUsesMsghdrIovecPayloadSections(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = 8
	ctx.Args = [6]uint64{1, 0x1000, 0}
	ctx.Opts.TraceWriteFDs = map[int32]bool{1: true}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0x2000, 2, 0, 0, 0)},
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, UserLen: iovecSize * 2, CopiedLen: iovecSize * 2, ProbeRet: 0, Data: iovecBytes([2]uint64{0x3000, 3}, [2]uint64{0x4000, 5})},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x3000, UserLen: 3, CopiedLen: 3, ProbeRet: 0, Data: []byte("012")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 1), UserPtr: 0x4000, UserLen: 5, CopiedLen: 5, ProbeRet: 0, Data: []byte("34567")},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="012", iov_len=3}, {iov_base="34567", iov_len=5}], msg_iovlen=2, msg_controllen=0, msg_flags=0}`
	assertArgParts(t, "sendmsg", res.ArgParts, []string{"1", wantMsg, "0"})
	for _, want := range []string{
		" * 3 bytes in buffer 0\n | 00000  30 31 32",
		" * 5 bytes in buffer 1\n | 00000  33 34 35 36 37",
	} {
		if !strings.Contains(res.HexDumpStr, want) {
			t.Fatalf("sendmsg dump missing %q in:\n%s", want, res.HexDumpStr)
		}
	}
}

func TestRecvmsgHandlerUsesExitMsghdrAndLimitsIovecDumpByReturnValue(t *testing.T) {
	ctx := newMsgPolicyContext("recvmsg")
	ctx.Ret = 7
	ctx.Args = [6]uint64{0, 0x1000, 0}
	ctx.Opts.TraceReadFDs = map[int32]bool{0: true}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0x2000, 2, 0, 0, 0)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0x2000, 2, 0, 0, 0)},
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, UserLen: iovecSize * 2, CopiedLen: iovecSize * 2, ProbeRet: 0, Data: iovecBytes([2]uint64{0x3000, 8}, [2]uint64{0x4000, 15})},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x3000, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: []byte("89abcde\xff")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: iovecBasePayloadArgIndex(1, 1), UserPtr: 0x4000, UserLen: 15, CopiedLen: 8, ProbeRet: 0, Data: []byte("\xff\xff\xff\xff\xff\xff\xff\xff")},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="89abcde", iov_len=8}, {iov_base="", iov_len=15}], msg_iovlen=2, msg_controllen=0, msg_flags=0}`
	assertArgParts(t, "recvmsg", res.ArgParts, []string{"0", wantMsg, "0"})
	if !strings.Contains(res.HexDumpStr, " * 7 bytes in buffer 0\n | 00000  38 39 61 62 63 64 65") {
		t.Fatalf("recvmsg dump missing returned bytes:\n%s", res.HexDumpStr)
	}
	if strings.Contains(res.HexDumpStr, "buffer 1") || strings.Contains(res.HexDumpStr, "ff ff") {
		t.Fatalf("recvmsg dump included bytes beyond return value:\n%s", res.HexDumpStr)
	}
}

func TestRecvmsgHandlerFormatsMsgNameSockaddrSection(t *testing.T) {
	ctx := newMsgPolicyContext("recvmsg")
	ctx.Ret = 1
	ctx.Args = [6]uint64{3, 0x1000, 0}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0x4000, 110, 0x2000, 1, 0, 0, 0)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0x4000, 36, 0x2000, 1, 0, 0, 0)},
		{Kind: PayloadKindSockaddr, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x4000, UserLen: 36, CopiedLen: 36, ProbeRet: 0, Data: unixSockaddrBytes("msg_name-recvmsg.test.send.socket", 36)},
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, UserLen: iovecSize, CopiedLen: iovecSize, ProbeRet: 0, Data: iovecBytes([2]uint64{0x3000, 1})},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x3000, UserLen: 1, CopiedLen: 1, ProbeRet: 0, Data: []byte("A")},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name={sa_family=AF_UNIX, sun_path="msg_name-recvmsg.test.send.socket"}, msg_namelen=110 => 36, msg_iov=[{iov_base="A", iov_len=1}], msg_iovlen=1, msg_controllen=0, msg_flags=0}`
	assertArgParts(t, "recvmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestSendmsgHandlerFormatsControlMessageSection(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := cmsgRightsBytes(-1, -2)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=24, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[-1, -2]}], msg_controllen=24, msg_flags=0}`
	assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestRecvmsgHandlerFormatsControlMessageFromExitSection(t *testing.T) {
	ctx := newMsgPolicyContext("recvmsg")
	ctx.Ret = 1
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := cmsgRightsBytes(7)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=20, cmsg_level=SOL_SOCKET, cmsg_type=SCM_RIGHTS, cmsg_data=[7]}], msg_controllen=24, msg_flags=0}`
	assertArgParts(t, "recvmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestSendmsgHandlerFallsBackToControlPointerWithoutCmsgSection(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, 24, 0)},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=0x5000, msg_controllen=24, msg_flags=0}`
	assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestSendmsgHandlerFormatsSecurityControlMessageAsText(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := cmsgBytes(solSocket, scmSecurity, []byte("secret"))
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=22, cmsg_level=SOL_SOCKET, cmsg_type=SCM_SECURITY, cmsg_data="secret"}], msg_controllen=24, msg_flags=0}`
	assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestRecvmsgHandlerFormatsCredentialsControlMessage(t *testing.T) {
	ctx := newMsgPolicyContext("recvmsg")
	ctx.Ret = 1
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := cmsgCredentialsBytes(1234, 1000, 1001)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=28, cmsg_level=SOL_SOCKET, cmsg_type=SCM_CREDENTIALS, cmsg_data={pid=1234, uid=1000, gid=1001}}], msg_controllen=32, msg_flags=0}`
	assertArgParts(t, "recvmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestSendmsgHandlerFormatsShortCredentialsControlDataAsHex(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := cmsgBytes(solSocket, scmCredentials, []byte("short"))
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=21, cmsg_level=SOL_SOCKET, cmsg_type=SCM_CREDENTIALS, cmsg_data="\x73\x68\x6f\x72\x74"}], msg_controllen=24, msg_flags=0}`
	assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestSendmsgHandlerFormatsUnknownSocketControlDataAsHex(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := cmsgBytes(solSocket, 0xfacefeed, []byte("A"))
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=17, cmsg_level=SOL_SOCKET, cmsg_type=0xfacefeed /* SCM_??? */, cmsg_data="\x41"}], msg_controllen=24, msg_flags=0}`
	assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestSendmsgHandlerFormatsUnknownLevelControlDataAsHex(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := cmsgBytes(solTCP, 0xdeadbeef, []byte("A"))
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=17, cmsg_level=SOL_TCP, cmsg_type=0xdeadbeef, cmsg_data="\x41"}], msg_controllen=24, msg_flags=0}`
	assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestSendmsgHandlerFormatsUnknownIPControlTypeComment(t *testing.T) {
	ctx := newMsgPolicyContext("sendmsg")
	ctx.Ret = -9
	ctx.Args = [6]uint64{3, 0x1000, 0}
	control := cmsgBytes(solIP, 0xfacefeed, nil)
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0, 0, 0, 0, 0x5000, uint64(len(control)), 0)},
		{Kind: PayloadKindCmsg, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x5000, UserLen: uint32(len(control)), CopiedLen: uint32(len(control)), ProbeRet: 0, Data: control},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name=NULL, msg_namelen=0, msg_iov=NULL, msg_iovlen=0, msg_control=[{cmsg_len=16, cmsg_level=SOL_IP, cmsg_type=0xfacefeed /* IP_??? */}], msg_controllen=16, msg_flags=0}`
	assertArgParts(t, "sendmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestRecvmsgHandlerLimitsMsgNameDisplayByEnterNameLen(t *testing.T) {
	ctx := newMsgPolicyContext("recvmsg")
	ctx.Ret = 1
	ctx.Args = [6]uint64{3, 0x1000, 0}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0x4000, 2, 0x2000, 1, 0, 0, 0)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0x4000, 36, 0x2000, 1, 0, 0, 0)},
		{Kind: PayloadKindSockaddr, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x4000, UserLen: 36, CopiedLen: 2, ProbeRet: 0, Data: unixSockaddrBytes("AAAAAAAAAAAAAAAA", 2)},
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, UserLen: iovecSize, CopiedLen: iovecSize, ProbeRet: 0, Data: iovecBytes([2]uint64{0x3000, 1})},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x3000, UserLen: 1, CopiedLen: 1, ProbeRet: 0, Data: []byte("A")},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `{msg_name={sa_family=AF_UNIX}, msg_namelen=2 => 36, msg_iov=[{iov_base="A", iov_len=1}], msg_iovlen=1, msg_controllen=0, msg_flags=0}`
	assertArgParts(t, "recvmsg", res.ArgParts, []string{"3", wantMsg, "0"})
}

func TestRecvmsgHandlerFormatsEFAULTMsghdrAsNameLenOnly(t *testing.T) {
	ctx := newMsgPolicyContext("recvmsg")
	ctx.Ret = recvmsgEFAULT
	ctx.Args = [6]uint64{3, 0x1000, 0}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: msghdrSnapshotSize, CopiedLen: msghdrSnapshotSize, ProbeRet: 0, Data: msghdrBytes(0x4000, 36, 0x2000, 1, 0, 0, 0)},
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, UserLen: iovecSize, CopiedLen: iovecSize, ProbeRet: 0, Data: iovecBytes([2]uint64{0x3000, 1})},
	}

	res := (&MsgHandler{}).Handle(ctx)

	assertArgParts(t, "recvmsg", res.ArgParts, []string{"3", "{msg_namelen=36}", "0"})
}

func TestSendmmsgHandlerUsesExitMsgLenAndInputPayloadSections(t *testing.T) {
	ctx := newMsgPolicyContext("sendmmsg")
	ctx.Ret = 2
	ctx.Args = [6]uint64{1, 0x1000, 2, 0x4004}
	ctx.Opts.TraceWriteFDs = map[int32]bool{1: true}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: 2 * mmsghdrSnapshotSize, CopiedLen: 2 * mmsghdrSnapshotSize, ProbeRet: 0, Data: mmsghdrArrayBytes(
			mmsghdrBytes(0, 0, 0x2000, 2, 0, 0, 0, 0),
			mmsghdrBytes(0, 0, 0x5000, 1, 0, 0, 0, 0),
		)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x1000, UserLen: 2 * mmsghdrSnapshotSize, CopiedLen: 2 * mmsghdrSnapshotSize, ProbeRet: 0, Data: mmsghdrArrayBytes(
			mmsghdrBytes(0, 0, 0x2000, 2, 0, 0, 0, 8),
			mmsghdrBytes(0, 0, 0x5000, 1, 0, 0, 0, 7),
		)},
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, UserLen: iovecSize * 2, CopiedLen: iovecSize * 2, ProbeRet: 0, Data: iovecBytes([2]uint64{0x3000, 3}, [2]uint64{0x4000, 5})},
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: mmsghdrSecondIovArg, UserPtr: 0x5000, UserLen: iovecSize, CopiedLen: iovecSize, ProbeRet: 0, Data: iovecBytes([2]uint64{0x6000, 7})},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x3000, UserLen: 3, CopiedLen: 3, ProbeRet: 0, Data: []byte("012")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(1, 1), UserPtr: 0x4000, UserLen: 5, CopiedLen: 5, ProbeRet: 0, Data: []byte("34567")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionIn, ArgIndex: iovecBasePayloadArgIndex(mmsghdrSecondIovArg, 0), UserPtr: 0x6000, UserLen: 7, CopiedLen: 7, ProbeRet: 0, Data: []byte("89abcde")},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `[{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="012", iov_len=3}, {iov_base="34567", iov_len=5}], msg_iovlen=2, msg_controllen=0, msg_flags=0}, msg_len=8}, {msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="89abcde", iov_len=7}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=7}]`
	assertArgParts(t, "sendmmsg", res.ArgParts, []string{"1", wantMsg, "2", "MSG_DONTROUTE|MSG_NOSIGNAL"})
	for _, want := range []string{" = 2 buffers in vector 0\n", " = 1 buffers in vector 1\n"} {
		if !strings.Contains(res.HexDumpStr, want) {
			t.Fatalf("sendmmsg dump missing vector header %q in:\n%s", want, res.HexDumpStr)
		}
	}
	if !strings.Contains(res.HexDumpStr, " * 5 bytes in buffer 1\n | 00000  33 34 35 36 37") {
		t.Fatalf("sendmmsg dump missing second input buffer:\n%s", res.HexDumpStr)
	}
	if !strings.Contains(res.HexDumpStr, " * 7 bytes in buffer 0\n | 00000  38 39 61 62 63 64 65") {
		t.Fatalf("sendmmsg dump missing second message payload:\n%s", res.HexDumpStr)
	}
}

func TestRecvmmsgHandlerLimitsPayloadByFirstMsgLenNotMessageCount(t *testing.T) {
	ctx := newMsgPolicyContext("recvmmsg")
	ctx.Ret = 2
	ctx.Args = [6]uint64{0, 0x1000, 2, 0x40, 0}
	ctx.Opts.TraceReadFDs = map[int32]bool{0: true}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: 2 * mmsghdrSnapshotSize, CopiedLen: 2 * mmsghdrSnapshotSize, ProbeRet: 0, Data: mmsghdrArrayBytes(
			mmsghdrBytes(0, 0, 0x2000, 1, 0, 0, 0, 0),
			mmsghdrBytes(0, 0, 0x5000, 2, 0, 0, 0, 0),
		)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x1000, UserLen: 2 * mmsghdrSnapshotSize, CopiedLen: 2 * mmsghdrSnapshotSize, ProbeRet: 0, Data: mmsghdrArrayBytes(
			mmsghdrBytes(0, 0, 0x2000, 1, 0, 0, 0, 7),
			mmsghdrBytes(0, 0, 0x5000, 2, 0, 0, 0, 7),
		)},
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, UserLen: iovecSize, CopiedLen: iovecSize, ProbeRet: 0, Data: iovecBytes([2]uint64{0x3000, 8})},
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: mmsghdrSecondIovArg, UserPtr: 0x5000, UserLen: iovecSize * 2, CopiedLen: iovecSize * 2, ProbeRet: 0, Data: iovecBytes([2]uint64{0x6000, 7}, [2]uint64{0x7000, 7})},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x3000, UserLen: 8, CopiedLen: 8, ProbeRet: 0, Data: []byte("89abcde\xff")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: iovecBasePayloadArgIndex(mmsghdrSecondIovArg, 0), UserPtr: 0x6000, UserLen: 7, CopiedLen: 7, ProbeRet: 0, Data: []byte("1234567")},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: iovecBasePayloadArgIndex(mmsghdrSecondIovArg, 1), UserPtr: 0x7000, UserLen: 7, CopiedLen: 7, ProbeRet: 0, Data: []byte("\xff\xff\xff\xff\xff\xff\xff")},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `[{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="89abcde", iov_len=8}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=7}, {msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="1234567", iov_len=7}, {iov_base="", iov_len=7}], msg_iovlen=2, msg_controllen=0, msg_flags=0}, msg_len=7}]`
	assertArgParts(t, "recvmmsg", res.ArgParts, []string{"0", wantMsg, "2", "MSG_DONTWAIT", "NULL"})
	for _, want := range []string{" = 1 buffers in vector 0\n", " = 2 buffers in vector 1\n"} {
		if !strings.Contains(res.HexDumpStr, want) {
			t.Fatalf("recvmmsg dump missing vector header %q in:\n%s", want, res.HexDumpStr)
		}
	}
	if !strings.Contains(res.HexDumpStr, " * 7 bytes in buffer 0\n | 00000  38 39 61 62 63 64 65") {
		t.Fatalf("recvmmsg dump missing msg_len bytes:\n%s", res.HexDumpStr)
	}
	if strings.Contains(res.HexDumpStr, "ff ff") {
		t.Fatalf("recvmmsg dump used message count or full iov length instead of msg_len:\n%s", res.HexDumpStr)
	}
}

func TestRecvmmsgHandlerFormatsTimeoutAndLeftReturnDesc(t *testing.T) {
	ctx := newMsgPolicyContext("recvmmsg")
	ctx.Ret = 1
	ctx.Args = [6]uint64{3, 0x1000, 1, 0, 0x4000}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: mmsghdrSnapshotSize, CopiedLen: mmsghdrSnapshotSize, ProbeRet: 0, Data: mmsghdrArrayBytes(
			mmsghdrBytes(0, 0, 0x2000, 1, 0, 0, 0, 0),
		)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, UserPtr: 0x1000, UserLen: mmsghdrSnapshotSize, CopiedLen: mmsghdrSnapshotSize, ProbeRet: 0, Data: mmsghdrArrayBytes(
			mmsghdrBytes(0, 0, 0x2000, 1, 0, 0, 0, 1),
		)},
		{Kind: PayloadKindIovec, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x2000, UserLen: iovecSize, CopiedLen: iovecSize, ProbeRet: 0, Data: iovecBytes([2]uint64{0x3000, 1})},
		{Kind: PayloadKindBytes, Direction: PayloadDirectionOut, ArgIndex: iovecBasePayloadArgIndex(1, 0), UserPtr: 0x3000, UserLen: 1, CopiedLen: 1, ProbeRet: 0, Data: []byte("A")},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 4, UserPtr: 0x4000, UserLen: timespecSize, CopiedLen: timespecSize, ProbeRet: 0, Data: msgTimespecBytes(0, 12345678)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 4, UserPtr: 0x4000, UserLen: timespecSize, CopiedLen: timespecSize, ProbeRet: 0, Data: msgTimespecBytes(0, 12341156)},
	}

	res := (&MsgHandler{}).Handle(ctx)

	wantMsg := `[{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="A", iov_len=1}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=1}]`
	assertArgParts(t, "recvmmsg", res.ArgParts, []string{"3", wantMsg, "1", "0", "{tv_sec=0, tv_nsec=12345678}"})
	if res.ReturnDesc != "left {tv_sec=0, tv_nsec=12341156}" {
		t.Fatalf("ReturnDesc = %q", res.ReturnDesc)
	}
}

func TestRecvmmsgHandlerUsesPointerForFailedTimeoutCase(t *testing.T) {
	ctx := newMsgPolicyContext("recvmmsg")
	ctx.Ret = -22
	ctx.Args = [6]uint64{3, 0x1000, 1, 0, 0x4000}
	ctx.PayloadSections = []PayloadSection{
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, UserPtr: 0x1000, UserLen: mmsghdrSnapshotSize, CopiedLen: mmsghdrSnapshotSize, ProbeRet: 0, Data: mmsghdrArrayBytes(
			mmsghdrBytes(0, 0, 0x2000, 1, 0, 0, 0, 1),
		)},
		{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 4, UserPtr: 0x4000, UserLen: timespecSize, CopiedLen: timespecSize, ProbeRet: 0, Data: msgTimespecBytes(0xdeadbeef, 0xfacefeed)},
	}

	res := (&MsgHandler{}).Handle(ctx)

	assertArgParts(t, "recvmmsg", res.ArgParts, []string{"3", "0x1000", "1", "0", "{tv_sec=3735928559, tv_nsec=4207869677}"})
	if res.ReturnDesc != "" {
		t.Fatalf("ReturnDesc = %q, want empty", res.ReturnDesc)
	}
}

func newMsgPolicyContext(name string) *Context {
	return &Context{
		Pid:       1234,
		Tid:       1234,
		TargetPid: 1234,
		SysName:   name,
		ScMeta:    meta.Syscall{Name: name},
		Decoder:   event.NewDecoder(),
		Opts:      &cli.Options{StringLimit: 32, TraceReadFDs: map[int32]bool{}, TraceWriteFDs: map[int32]bool{}},
	}
}

func msghdrBytes(name uint64, nameLen uint32, iov uint64, iovLen uint64, control uint64, controlLen uint64, flags uint32) []byte {
	data := make([]byte, msghdrSnapshotSize)
	binary.LittleEndian.PutUint64(data[msghdrNameOffset:msghdrNameOffset+8], name)
	binary.LittleEndian.PutUint32(data[msghdrNameLenOffset:msghdrNameLenOffset+4], nameLen)
	binary.LittleEndian.PutUint64(data[msghdrIovOffset:msghdrIovOffset+8], iov)
	binary.LittleEndian.PutUint64(data[msghdrIovLenOffset:msghdrIovLenOffset+8], iovLen)
	binary.LittleEndian.PutUint64(data[msghdrControlOffset:msghdrControlOffset+8], control)
	binary.LittleEndian.PutUint64(data[msghdrControlLenOffset:msghdrControlLenOffset+8], controlLen)
	binary.LittleEndian.PutUint32(data[msghdrFlagsOffset:msghdrFlagsOffset+4], flags)
	return data
}

func mmsghdrBytes(name uint64, nameLen uint32, iov uint64, iovLen uint64, control uint64, controlLen uint64, flags uint32, msgLen uint32) []byte {
	data := make([]byte, mmsghdrSnapshotSize)
	copy(data, msghdrBytes(name, nameLen, iov, iovLen, control, controlLen, flags))
	binary.LittleEndian.PutUint32(data[mmsghdrMsgLenOffset:mmsghdrMsgLenOffset+4], msgLen)
	return data
}

func mmsghdrArrayBytes(items ...[]byte) []byte {
	var data []byte
	for _, item := range items {
		data = append(data, item...)
	}
	return data
}

func unixSockaddrBytes(path string, length int) []byte {
	data := make([]byte, length)
	binary.LittleEndian.PutUint16(data[0:2], 1)
	copy(data[2:], []byte(path))
	return data
}

func msgTimespecBytes(sec int64, nsec uint64) []byte {
	data := make([]byte, timespecSize)
	binary.LittleEndian.PutUint64(data[0:8], uint64(sec))
	binary.LittleEndian.PutUint64(data[8:16], nsec)
	return data
}

func cmsgRightsBytes(fds ...int32) []byte {
	data := cmsgBytes(solSocket, scmRights, make([]byte, len(fds)*4))
	for i, fd := range fds {
		binary.LittleEndian.PutUint32(data[cmsgHeaderSize+i*4:cmsgHeaderSize+i*4+4], uint32(fd))
	}
	return data
}

func cmsgCredentialsBytes(pid int32, uid uint32, gid uint32) []byte {
	data := cmsgBytes(solSocket, scmCredentials, make([]byte, cmsgUcredSize))
	binary.LittleEndian.PutUint32(data[cmsgHeaderSize:cmsgHeaderSize+4], uint32(pid))
	binary.LittleEndian.PutUint32(data[cmsgHeaderSize+4:cmsgHeaderSize+8], uid)
	binary.LittleEndian.PutUint32(data[cmsgHeaderSize+8:cmsgHeaderSize+12], gid)
	return data
}

func cmsgBytes(level uint32, cmsgType uint32, payload []byte) []byte {
	cmsgLen := cmsgHeaderSize + len(payload)
	data := make([]byte, alignCmsgLen(cmsgLen))
	binary.LittleEndian.PutUint64(data[0:8], uint64(cmsgLen))
	binary.LittleEndian.PutUint32(data[8:12], level)
	binary.LittleEndian.PutUint32(data[12:16], cmsgType)
	copy(data[cmsgHeaderSize:], payload)
	return data
}
