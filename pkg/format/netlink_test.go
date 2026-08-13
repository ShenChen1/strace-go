package format_test

import (
	"encoding/binary"
	"fmt"
	"testing"

	"strace-go/pkg/format"
)

type netlinkCatalogStub struct{}

func (netlinkCatalogStub) DecodeFlags(value uint64, tableName string) string {
	switch tableName {
	case "netlink_types":
		return fmt.Sprintf("TYPE_%d", value)
	case "netlink_flags":
		return fmt.Sprintf("FLAGS_%d", value)
	case "errno":
		return fmt.Sprintf("ERRNO_%d", value)
	default:
		return fmt.Sprintf("VALUE_%d", value)
	}
}

func TestNetlinkWithCatalogFormatsAlignedMessages(t *testing.T) {
	first := netlinkMessage(17, 16, 1, 7, 9, []byte{'a'})
	second := netlinkMessage(16, 3, 0, 8, 10, nil)
	data := append(first, make([]byte, 3)...)
	data = append(data, second...)

	got := format.NetlinkWithCatalog(netlinkCatalogStub{}, data)
	want := `[{nlmsg_len=17, nlmsg_type=TYPE_16, nlmsg_flags=FLAGS_1, nlmsg_seq=7, nlmsg_pid=9}, "a", {nlmsg_len=16, nlmsg_type=TYPE_3, nlmsg_flags=FLAGS_0, nlmsg_seq=8, nlmsg_pid=10}]`
	if got != want {
		t.Fatalf("NetlinkWithCatalog() = %q, want %q", got, want)
	}
}

func TestNetlinkWithCatalogFormatsNestedError(t *testing.T) {
	nested := netlinkMessage(16, 3, 0, 2, 4, nil)
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint32(payload, ^uint32(1))
	payload = append(payload, nested...)
	data := netlinkMessage(uint32(16+len(payload)), 2, 4, 1, 3, payload)

	got := format.NetlinkWithCatalog(netlinkCatalogStub{}, data)
	want := `{nlmsg_len=36, nlmsg_type=TYPE_2, nlmsg_flags=FLAGS_4, nlmsg_seq=1, nlmsg_pid=3}, {error=-ERRNO_2, msg={nlmsg_len=16, nlmsg_type=TYPE_3, nlmsg_flags=FLAGS_0, nlmsg_seq=2, nlmsg_pid=4}}`
	if got != want {
		t.Fatalf("NetlinkWithCatalog() = %q, want %q", got, want)
	}
}

func TestNetlinkWithCatalogStopsOnMalformedLength(t *testing.T) {
	data := netlinkMessage(8, 16, 1, 7, 9, []byte{'x'})

	got := format.NetlinkWithCatalog(netlinkCatalogStub{}, data)
	want := `{nlmsg_len=8, nlmsg_type=TYPE_16, nlmsg_flags=FLAGS_1, nlmsg_seq=7, nlmsg_pid=9}`
	if got != want {
		t.Fatalf("NetlinkWithCatalog() = %q, want %q", got, want)
	}
}

func TestNetlinkWithCatalogClipsOverlongSnapshot(t *testing.T) {
	data := netlinkMessage(64, 16, 1, 7, 9, nil)

	got := format.NetlinkWithCatalog(netlinkCatalogStub{}, data)
	want := `{nlmsg_len=16, nlmsg_type=TYPE_16, nlmsg_flags=FLAGS_1, nlmsg_seq=7, nlmsg_pid=9}`
	if got != want {
		t.Fatalf("NetlinkWithCatalog() = %q, want %q", got, want)
	}
}

func netlinkMessage(length uint32, messageType, flags uint16, seq, pid uint32, payload []byte) []byte {
	data := make([]byte, 16+len(payload))
	binary.LittleEndian.PutUint32(data[0:4], length)
	binary.LittleEndian.PutUint16(data[4:6], messageType)
	binary.LittleEndian.PutUint16(data[6:8], flags)
	binary.LittleEndian.PutUint32(data[8:12], seq)
	binary.LittleEndian.PutUint32(data[12:16], pid)
	copy(data[16:], payload)
	return data
}
