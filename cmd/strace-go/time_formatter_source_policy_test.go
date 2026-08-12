package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestTimeFormatterUsesSessionClockSource(t *testing.T) {
	source := readTextFile(t, filepath.Join(repoRootForTest(t), "cmd/strace-go/time_formatter.go"))
	for _, forbidden := range []string{"time.Now()", "systemTraceClock{}", "if clock == nil"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("TimeFormatter must not contain %q", forbidden)
		}
	}
	for _, snippet := range []string{"clock traceClock", "tf.clock.NowMonoNs()"} {
		if !strings.Contains(source, snippet) {
			t.Fatalf("TimeFormatter clock boundary missing %q", snippet)
		}
	}
}
