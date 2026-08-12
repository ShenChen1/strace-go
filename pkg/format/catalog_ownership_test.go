package format

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type flagDecoderTestStub struct{}

func (flagDecoderTestStub) DecodeFlags(uint64, string) string {
	return "flag-port"
}

func TestFormatSourceDoesNotConstructCatalog(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(currentFile)
	for _, name := range []string{"format_socket.go", "netlink.go"} {
		source, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(source), "meta.NewCatalog(") {
			t.Fatalf("%s still constructs an implicit Catalog", name)
		}
		if strings.Contains(string(source), "*meta.Catalog") {
			t.Fatalf("%s still exposes concrete meta.Catalog", name)
		}
	}
}

func TestCatalogFormattersAcceptFlagDecoder(t *testing.T) {
	got := EpollEventWithCatalog(flagDecoderTestStub{}, make([]byte, 12))
	want := "{events=flag-port, data={u32=0, u64=0x0}}"
	if got != want {
		t.Fatalf("EpollEventWithCatalog() = %q, want %q", got, want)
	}
}
