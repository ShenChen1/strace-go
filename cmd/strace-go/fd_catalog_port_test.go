package main

import "testing"

type fdFlagDecoderTestStub struct{}

func (fdFlagDecoderTestStub) DecodeFlags(value uint64, tableName string) string {
	switch tableName {
	case "addrfams":
		return "family"
	case "netlink_protocols":
		return "protocol"
	default:
		return "unknown"
	}
}

var _ fdFlagDecoder = fdFlagDecoderTestStub{}

func TestSocketFDInfoUsesFlagDecoderPort(t *testing.T) {
	view := syscallEventView{args: [6]uint64{16, 2, 4}}
	if got := socketFDInfoFromFlags(fdFlagDecoderTestStub{}, view); got != "family:protocol" {
		t.Fatalf("socket fd info = %q, want family:protocol", got)
	}
}

func TestSocketFDInfoWithNilFlagDecoderIsInert(t *testing.T) {
	view := syscallEventView{args: [6]uint64{2, 1, 0}}
	if got := socketFDInfoFromFlags(nil, view); got != "" {
		t.Fatalf("nil socket fd info = %q, want empty", got)
	}
}
