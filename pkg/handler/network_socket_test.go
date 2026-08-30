package handler

import (
	"encoding/binary"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/meta"
)

func TestNetworkSocketFormatsNetlinkArguments(t *testing.T) {
	ctx := newNetworkPolicyContext(nil, "socket")
	ctx.ScMeta = meta.Syscall{
		Name:     "socket",
		Args:     []string{"family", "type", "protocol"},
		ArgTypes: []string{"int", "int", "int"},
	}
	ctx.Args = [6]uint64{16, 3, 4}

	got := (&NetworkHandler{}).Handle(ctx).ArgParts
	want := []string{"AF_NETLINK", "SOCK_RAW", "NETLINK_SOCK_DIAG"}
	if len(got) != len(want) {
		t.Fatalf("socket args = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("socket arg %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestNetworkFDUsesSelectedSocketDetails(t *testing.T) {
	ctx := newNetworkPolicyContext(nil, "bind")
	ctx.ScMeta = meta.Syscall{
		Name:     "bind",
		Args:     []string{"fd", "umyaddr", "addrlen"},
		ArgTypes: []string{"int", "struct sockaddr *", "int"},
	}
	ctx.Args = [6]uint64{7, 0, 0}
	ctx.Opts = cli.ParseArgs([]string{"--decode-fds=socket", "/bin/true"})
	ctx.FDStateView = testFDStateView{paths: map[string]string{
		"1234:7": "socket:[42]|AF_NETLINK:NETLINK_SOCK_DIAG",
	}}

	got := (&NetworkHandler{}).Handle(ctx).ArgParts
	if len(got) == 0 || got[0] != "7<NETLINK:[42]>" {
		t.Fatalf("bind fd = %#v, want decorated netlink fd", got)
	}
}

func TestNetworkSockaddrFormatsNetlinkAddress(t *testing.T) {
	data := make([]byte, 12)
	binary.LittleEndian.PutUint16(data[0:2], 16)
	binary.LittleEndian.PutUint32(data[4:8], 1902433)
	binary.LittleEndian.PutUint32(data[8:12], 0)
	ctx := newNetworkPolicyContext(nil, "bind")
	ctx.Args = [6]uint64{7, 0x4000, uint64(len(data))}
	ctx.PayloadSections = []PayloadSection{{
		Kind:      PayloadKindStruct,
		Direction: PayloadDirectionIn,
		ArgIndex:  1,
		UserLen:   uint32(len(data)),
		CopiedLen: uint32(len(data)),
		ProbeRet:  0,
		Data:      data,
	}}

	got, ok := (&NetworkHandler{}).formatSockaddr(
		ctx, 1, "umyaddr", "struct sockaddr *", ctx.Args[1],
	)
	want := "{sa_family=AF_NETLINK, nl_pid=1902433, nl_groups=00000000}"
	if !ok || got != want {
		t.Fatalf("netlink sockaddr = %q, %v; want %q", got, ok, want)
	}
}
