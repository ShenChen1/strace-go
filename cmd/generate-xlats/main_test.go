package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestApplyStableXlatFallbacksAddsMissingEntries(t *testing.T) {
	prefix := ""
	entries := map[string]string{"O_CLOEXEC": "524288"}
	keys := []string{"O_CLOEXEC"}

	applyStableXlatFallbacks("uffd_flags", &prefix, entries, &keys)

	if prefix != "O_ UFFD_" {
		t.Fatalf("prefix = %q, want O_ UFFD_", prefix)
	}
	if entries["UFFD_USER_MODE_ONLY"] != "1" {
		t.Fatalf("UFFD_USER_MODE_ONLY = %q, want 1", entries["UFFD_USER_MODE_ONLY"])
	}
	if entries["O_CLOEXEC"] != "524288" {
		t.Fatalf("O_CLOEXEC was overwritten: %q", entries["O_CLOEXEC"])
	}
	if len(keys) != 3 {
		t.Fatalf("keys = %#v, want three stable entries", keys)
	}
}

func TestSortedKeysReturnsLexicalOrder(t *testing.T) {
	keys := sortedKeys(map[string]int{
		"write": 1,
		"open":  2,
		"close": 3,
	})
	want := []string{"close", "open", "write"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("sortedKeys() = %#v, want %#v", keys, want)
	}
}

func TestWriteSyscallArgXlatMapIsStable(t *testing.T) {
	var out bytes.Buffer
	writeSyscallArgXlatMap(&out, map[string]map[string]string{
		"write": {
			"z_arg": "last",
			"a_arg": "first",
		},
		"access": {
			"mode": "access_modes",
		},
		"dummy_table": {
			"dummy": "ignored",
		},
	})

	want := "var SyscallArgXlatMap = map[string]map[string]string{\n" +
		"\t\"access\": {\n" +
		"\t\t\"mode\": \"access_modes\",\n" +
		"\t},\n" +
		"\t\"write\": {\n" +
		"\t\t\"a_arg\": \"first\",\n" +
		"\t\t\"z_arg\": \"last\",\n" +
		"\t},\n" +
		"}\n"
	if out.String() != want {
		t.Fatalf("generated map:\n%s\nwant:\n%s", out.String(), want)
	}
}

func TestWriteGeneratedStaticXlatTablesKeepsStableOrder(t *testing.T) {
	var out bytes.Buffer
	missingIoctlFile := filepath.Join(t.TempDir(), "missing_ioctls_inc.h")

	writeGeneratedStaticXlatTables(&out, map[string]bool{}, missingIoctlFile)

	got := out.String()
	for _, want := range []string{
		`"pkey_access_rights"`,
		`"mmap_prot64"`,
		`"clocknames"`,
		`"signalnames"`,
		`"clone3_flags"`,
		`"x86_xfeatures"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("static xlat output missing %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"ioctl_cmds"`) {
		t.Fatalf("missing ioctl include emitted ioctl_cmds:\n%s", got)
	}
	if strings.Index(got, `"pkey_access_rights"`) > strings.Index(got, `"clocknames"`) {
		t.Fatalf("alias tables should be emitted before static tables:\n%s", got)
	}
}

func TestWriteIoctlXlatTableParsesDirectionAndValue(t *testing.T) {
	ioctlFile := filepath.Join(t.TempDir(), "ioctls_inc.h")
	content := []byte(`{ "linux/foo.h", "FOO_IOCTL", _IOC_READ|_IOC_WRITE, 4660, 4 },` + "\n")
	if err := os.WriteFile(ioctlFile, content, 0o600); err != nil {
		t.Fatalf("write temp ioctl include: %v", err)
	}

	var out bytes.Buffer
	writeIoctlXlatTable(&out, ioctlFile)

	got := out.String()
	for _, want := range []string{
		`"ioctl_cmds"`,
		`{Val: 3221492276, Str: "FOO_IOCTL"}, // From linux/foo.h`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("ioctl output missing %s:\n%s", want, got)
		}
	}
}
