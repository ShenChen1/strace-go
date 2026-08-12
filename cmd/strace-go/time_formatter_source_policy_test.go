package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTimeFormatterUsesSessionClockSource(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/time_formatter.go"))
	if strings.Contains(source, "time.Now()") {
		t.Fatal("TimeFormatter must not read the process clock directly")
	}
	for _, snippet := range []string{"clock traceClock", "tf.clock.NowMonoNs()"} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("TimeFormatter clock boundary missing %q", snippet)
		}
	}
}
