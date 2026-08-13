package format

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNetlinkEntryDelegatesToFormatter(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	source, err := os.ReadFile(filepath.Join(filepath.Dir(currentFile), "netlink.go"))
	if err != nil {
		t.Fatalf("read netlink.go: %v", err)
	}
	text := string(source)
	body := sourceFunctionBody(t, text, "func NetlinkWithCatalog")
	if !strings.Contains(text, "type netlinkFormatter struct") {
		t.Fatal("netlink formatter object is missing")
	}
	if !strings.Contains(body, "netlinkFormatter{catalog: catalog}.format(data)") {
		t.Fatal("NetlinkWithCatalog must delegate to netlinkFormatter")
	}
	for _, forbidden := range []string{"for len(curr)", "NetlinkWithCatalog(catalog, payload[4:])"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("NetlinkWithCatalog retains parser ownership %q", forbidden)
		}
	}
}

func sourceFunctionBody(t *testing.T, source, signature string) string {
	t.Helper()
	start := strings.Index(source, signature)
	if start < 0 {
		t.Fatalf("source missing function %q", signature)
	}
	rest := source[start:]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		return rest[:end]
	}
	return rest
}
