package format_test

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/internal/architecture"
	"strace-go/pkg/format"
	"strace-go/pkg/meta"
)

func TestStatWithCatalogFormatsDeviceByXlatMode(t *testing.T) {
	data := make([]byte, architecture.StatSize)
	binary.LittleEndian.PutUint64(data[0:8], 0xfc00)
	binary.LittleEndian.PutUint32(data[architecture.StatModeOffset:], 0100640)

	tests := []struct {
		mode     string
		wantDev  string
		wantMode string
	}{
		{mode: "raw", wantDev: "{st_dev=0xfc00,", wantMode: "st_mode=0100640,"},
		{mode: "abbrev", wantDev: "{st_dev=makedev(0xfc, 0),", wantMode: "st_mode=S_IFREG|0640,"},
		{mode: "verbose", wantDev: "{st_dev=0xfc00 /* makedev(0xfc, 0) */,", wantMode: "st_mode=0100640 /* S_IFREG|0640 */,"},
	}

	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			got := format.StatWithCatalog(meta.NewCatalog(test.mode), data)
			if !strings.HasPrefix(got, test.wantDev) || !strings.Contains(got, test.wantMode) {
				t.Fatalf("stat = %q, want device %q and mode %q", got, test.wantDev, test.wantMode)
			}
		})
	}
}

func TestStatWithCatalogRejectsShortBuffer(t *testing.T) {
	if got := format.StatWithCatalog(meta.NewCatalog("abbrev"), make([]byte, architecture.StatSize-1)); got != "{...}" {
		t.Fatalf("short stat = %q, want {…}", got)
	}
}
