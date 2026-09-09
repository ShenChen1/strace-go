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

func TestApplyStableXlatFallbacksAddsOpenat2Regular(t *testing.T) {
	prefix := ""
	entries := map[string]string{}
	keys := []string{}

	applyStableXlatFallbacks("openat2_flags", &prefix, entries, &keys)

	if prefix != "OPENAT2_" {
		t.Fatalf("openat2 prefix = %q, want OPENAT2_", prefix)
	}
	if entries["OPENAT2_REGULAR"] != "4294967296" {
		t.Fatalf("OPENAT2_REGULAR = %q, want 4294967296", entries["OPENAT2_REGULAR"])
	}
	if len(keys) != 1 || keys[0] != "OPENAT2_REGULAR" {
		t.Fatalf("openat2 keys = %#v, want OPENAT2_REGULAR", keys)
	}
}

func TestSignalFD4UsesGeneratedFlagXlat(t *testing.T) {
	argXlat := readArgXlatMap()
	if got := argXlat.Syscalls["signalfd4"]["flags"]; got != "sfd_flags" {
		t.Fatalf("signalfd4 flags xlat = %q, want sfd_flags", got)
	}
}

func TestOpenat2UsesGeneratedFlagXlat(t *testing.T) {
	if !allowedXlatNames(ArgXlatMap{})["openat2_flags"] {
		t.Fatal("openat2_flags is not always generated for the custom openat2 handler")
	}
}

func TestFlockUsesGeneratedOperationXlat(t *testing.T) {
	argXlat := readArgXlatMap()
	if got := argXlat.Syscalls["flock"]["op"]; got != "flockcmds" {
		t.Fatalf("flock operation xlat = %q, want flockcmds", got)
	}
}

func TestNormalizeXlatPrefixUsesOpenTreeUnknownContract(t *testing.T) {
	prefix := "OPEN_TREE_ AT_"
	normalizeXlatPrefix("open_tree_flags", &prefix)

	if prefix != "OPEN_TREE_" {
		t.Fatalf("open_tree prefix = %q, want OPEN_TREE_", prefix)
	}
}

func TestNormalizeXlatPrefixUsesSocketOptionUnknownContract(t *testing.T) {
	prefix := ""
	normalizeXlatPrefix("sock_options", &prefix)

	if prefix != "SO_" {
		t.Fatalf("sock_options prefix = %q, want SO_", prefix)
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

	want := "var generatedSyscallArgXlatMap = map[string]map[string]string{\n" +
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

func TestQuotaXlatsAreAlwaysGenerated(t *testing.T) {
	allowed := allowedXlatNames(ArgXlatMap{})
	for _, name := range []string{
		"quotacmds",
		"quotatypes",
		"quota_formats",
		"if_dqblk_valid",
		"if_dqinfo_flags",
		"if_dqinfo_valid",
		"xfs_dqblk_flags",
		"xfs_quota_flags",
	} {
		if !allowed[name] {
			t.Errorf("quota xlat %q is not generated", name)
		}
	}
	if !keepZeroXlatValue("USRQUOTA") {
		t.Fatal("USRQUOTA zero value must be preserved")
	}
}

func TestQuotaXlatCDefinitionsAreScoped(t *testing.T) {
	for _, name := range []string{"quotacmds", "xfs_dqblk_flags", "xfs_quota_flags"} {
		quotaProgram := newXlatCProgram(t.TempDir(), name).String()
		for _, want := range []string{
			"#include <linux/quota.h>",
			"#include <linux/dqblk_xfs.h>",
			"#define OLD_CMD(cmd)",
			"#define NEW_CMD(cmd)",
		} {
			if !strings.Contains(quotaProgram, want) {
				t.Errorf("%s C program missing %q", name, want)
			}
		}
	}

	otherProgram := newXlatCProgram(t.TempDir(), "fcntlcmds").String()
	for _, unwanted := range []string{
		"#include <linux/quota.h>",
		"#include <linux/dqblk_xfs.h>",
		"#define OLD_CMD(cmd)",
		"#define NEW_CMD(cmd)",
	} {
		if strings.Contains(otherProgram, unwanted) {
			t.Errorf("fcntlcmds C program unexpectedly contains %q", unwanted)
		}
	}
}

func TestAppendDerivedXlatTablesAddsDup3Flags(t *testing.T) {
	openFlags := xlatTableData{
		name:   "open_mode_flags",
		prefix: "O_",
		keys:   []string{"O_TRUNC", "O_CLOEXEC", "O_EMPTYPATH"},
		entries: map[string]string{
			"O_TRUNC":   "512",
			"O_CLOEXEC": "524288",
		},
	}

	tables := appendDerivedXlatTables(
		[]xlatTableData{openFlags},
		map[string]bool{"dup3_flags": true},
	)
	if len(tables) != 2 {
		t.Fatalf("derived tables = %d, want 2", len(tables))
	}
	dup3Flags := tables[1]
	if dup3Flags.name != "dup3_flags" {
		t.Fatalf("derived table name = %q, want dup3_flags", dup3Flags.name)
	}
	if !reflect.DeepEqual(dup3Flags.keys, openFlags.keys) {
		t.Fatalf("derived keys = %#v, want %#v", dup3Flags.keys, openFlags.keys)
	}

	var out bytes.Buffer
	writeXlatTable(&out, dup3Flags)
	for _, want := range []string{
		"O_TRUNC", "O_CLOEXEC", "O_EMPTYPATH", "O_LARGEFILE",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("derived dup3 table missing %s:\n%s", want, out.String())
		}
	}
}

func TestAppendDerivedXlatTablesKeepsExplicitDup3Flags(t *testing.T) {
	explicit := xlatTableData{
		name:    "dup3_flags",
		prefix:  "O_",
		keys:    []string{"O_CLOEXEC"},
		entries: map[string]string{"O_CLOEXEC": "524288"},
	}
	tables := appendDerivedXlatTables(
		[]xlatTableData{{name: "open_mode_flags"}, explicit},
		map[string]bool{"dup3_flags": true},
	)

	if len(tables) != 2 {
		t.Fatalf("derived tables = %d, want explicit table without duplicate", len(tables))
	}
	if !reflect.DeepEqual(tables[1], explicit) {
		t.Fatalf("explicit dup3 table changed: %#v", tables[1])
	}
}

func TestDerivedXlatSourceIsAllowed(t *testing.T) {
	argXlat := ArgXlatMap{Syscalls: map[string]map[string]string{
		"dup3": {"flags": "dup3_flags"},
	}}

	allowed := allowedXlatNames(argXlat)
	if !allowed["open_mode_flags"] {
		t.Fatal("dup3_flags did not enable its open_mode_flags source")
	}
}

func TestAppendDerivedXlatTablesRejectsMissingSource(t *testing.T) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("missing derived xlat source did not panic")
		}
		message, ok := recovered.(string)
		if !ok || !strings.Contains(message, "requires missing source") {
			t.Fatalf("unexpected panic: %#v", recovered)
		}
	}()

	appendDerivedXlatTables(nil, map[string]bool{"dup3_flags": true})
}
