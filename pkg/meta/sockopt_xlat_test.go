package meta_test

import (
	"fmt"
	"testing"
)

func TestDecodeSockoptTxrehashUnknownValues(t *testing.T) {
	tests := []struct {
		name string
		mode string
		val  uint64
		want string
	}{
		{name: "abbrev small", mode: "abbrev", val: 2, want: "2 /* SOCK_TXREHASH_??? */"},
		{name: "abbrev high", mode: "abbrev", val: 254, want: "254 /* SOCK_TXREHASH_??? */"},
		{name: "raw small", mode: "raw", val: 2, want: "2"},
		{name: "raw high", mode: "raw", val: 254, want: "254"},
		{name: "verbose small", mode: "verbose", val: 2, want: "2 /* SOCK_TXREHASH_??? */"},
		{name: "verbose high", mode: "verbose", val: 254, want: "254 /* SOCK_TXREHASH_??? */"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeFlagsForTest(tt.mode, tt.val, "sockopt_txrehash_vals"); got != tt.want {
				t.Fatalf("DecodeFlags(%d, sockopt_txrehash_vals) in %s mode = %q, want %q", tt.val, tt.mode, got, tt.want)
			}
		})
	}
}

func TestDecodeSocketLayerAndNetlinkOptions(t *testing.T) {
	tests := []struct {
		name string
		val  uint64
		xlat string
		want string
	}{
		{name: "netlink level", val: 270, xlat: "socketlayers", want: "SOL_NETLINK"},
		{name: "netlink option", val: 1, xlat: "sock_netlink_options", want: "NETLINK_ADD_MEMBERSHIP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeFlagsForTest("abbrev", tt.val, tt.xlat); got != tt.want {
				t.Fatalf("DecodeFlags(%d, %q) = %q, want %q", tt.val, tt.xlat, got, tt.want)
			}
		})
	}
}

func TestDecodeUnknownSocketOptionUsesPrefixComment(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want string
	}{
		{name: "abbrev", mode: "abbrev", want: "0x4e /* SO_??? */"},
		{name: "raw", mode: "raw", want: "0x4e"},
		{name: "verbose", mode: "verbose", want: "0x4e /* SO_??? */"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeFlagsForTest(tt.mode, 78, "sock_options"); got != tt.want {
				t.Fatalf("DecodeFlags(78, sock_options) in %s mode = %q, want %q", tt.mode, got, tt.want)
			}
		})
	}
}

func TestDecodeSocketLayerVerboseUsesHexRawValue(t *testing.T) {
	for _, mode := range []string{"raw", "verbose"} {
		tests := []struct {
			val  uint64
			name string
		}{
			{val: 1, name: "SOL_SOCKET"},
			{val: 270, name: "SOL_NETLINK"},
		}
		for _, tt := range tests {
			t.Run(mode+"/"+tt.name, func(t *testing.T) {
				want := fmt.Sprintf("%#x", tt.val)
				if mode == "verbose" {
					want += " /* " + tt.name + " */"
				}
				if got := decodeFlagsForTest(mode, tt.val, "socketlayers"); got != want {
					t.Fatalf("DecodeFlags(%d, socketlayers) in %s mode = %q, want %q", tt.val, mode, got, want)
				}
			})
		}
	}
}

func TestDecodeSockoptRawTruncatesAbiWord(t *testing.T) {
	for _, xlat := range []string{"socketlayers", "sock_options"} {
		t.Run(xlat, func(t *testing.T) {
			if got := decodeFlagsForTest("raw", 0xdefaced00000001, xlat); got != "0x1" {
				t.Fatalf("DecodeFlags(abi word, %s) = %q, want 0x1", xlat, got)
			}
		})
	}
}
