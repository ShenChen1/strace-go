package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureManifestRendersCheckedInFiles(t *testing.T) {
	manifest := newCaptureManifest()
	header, err := renderCaptureHeader(manifest)
	if err != nil {
		t.Fatalf("render header: %v", err)
	}
	goSource, err := renderCaptureGo(manifest)
	if err != nil {
		t.Fatalf("render Go source: %v", err)
	}
	root, err := findCaptureManifestRepoRoot()
	if err != nil {
		t.Fatalf("find repository root: %v", err)
	}
	if err := checkCaptureManifestFile(filepath.Join(root, defaultCaptureHeaderPath), header); err != nil {
		t.Fatal(err)
	}
	if err := checkCaptureManifestFile(filepath.Join(root, defaultCaptureGoPath), goSource); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"STRACE_GO_CAPTURE_ROUTE_MAP_MAX_ENTRIES 512",
		"enum enter_prog_index",
		"enum exit_prog_index",
	} {
		if !strings.Contains(header, want) {
			t.Errorf("generated header missing %q", want)
		}
	}
	if !strings.Contains(goSource, "bpfSyscallProgramRoots") {
		t.Error("generated Go source missing auxiliary roots")
	}
}

func TestCaptureManifestRoutesTimeOutputThroughFDTime(t *testing.T) {
	for _, route := range captureRouteSpecs() {
		if route.syscallName != "time" {
			continue
		}
		if route.enterProgram != "" || route.exitProgram != "exit_fd_time" {
			t.Fatalf("time route = enter %q, exit %q", route.enterProgram, route.exitProgram)
		}
		return
	}
	t.Fatal("time capture route is missing")
}

func TestCaptureManifestRoutesFileAttributesThroughDedicatedFamilies(t *testing.T) {
	want := map[string]struct {
		enter string
		exit  string
	}{
		"file_getattr": {enter: "enter_path_only", exit: "exit_struct"},
		"file_setattr": {enter: "enter_fs", exit: ""},
	}
	for name, expected := range want {
		for _, route := range captureRouteSpecs() {
			if route.syscallName != name {
				continue
			}
			if route.enterProgram != expected.enter || route.exitProgram != expected.exit {
				t.Fatalf("%s route = enter %q, exit %q; want enter %q, exit %q", name, route.enterProgram, route.exitProgram, expected.enter, expected.exit)
			}
			delete(want, name)
			break
		}
	}
	for name := range want {
		t.Fatalf("%s capture route is missing", name)
	}
}

func TestCaptureManifestValidationRejectsInvalidReferences(t *testing.T) {
	tests := []struct {
		name string
		edit func(*captureManifest)
		want string
	}{
		{
			name: "duplicate slot",
			edit: func(manifest *captureManifest) {
				duplicate := manifest.programs[0]
				duplicate.programName = "enter_duplicate"
				duplicate.goName = "enterProgDuplicate"
				duplicate.cName = "ENTER_PROG_DUPLICATE"
				manifest.programs = append(manifest.programs, duplicate)
			},
			want: "duplicate slot",
		},
		{
			name: "duplicate symbol",
			edit: func(manifest *captureManifest) {
				manifest.programs[1].programName = "enter_duplicate"
				manifest.programs[1].goName = manifest.programs[0].goName
			},
			want: "duplicate Go slot name",
		},
		{
			name: "unknown family",
			edit: func(manifest *captureManifest) {
				manifest.programs[0].familyGoName = "unknownFamily"
			},
			want: "unknown handler family",
		},
		{
			name: "unknown route program",
			edit: func(manifest *captureManifest) {
				manifest.routes[0].enterProgram = "missing_program"
			},
			want: "references unknown enter program",
		},
		{
			name: "wrong route direction",
			edit: func(manifest *captureManifest) {
				manifest.routes[0].enterProgram = "exit_generic"
			},
			want: "references non-enter program",
		},
		{
			name: "non direct route",
			edit: func(manifest *captureManifest) {
				manifest.routes[0].enterProgram = "enter_nested_fd_path0"
			},
			want: "references non-direct enter program",
		},
		{
			name: "invalid elision",
			edit: func(manifest *captureManifest) {
				manifest.routes[0].standaloneExitElision = true
			},
			want: "invalid standalone exit elision",
		},
		{
			name: "dependency cycle",
			edit: func(manifest *captureManifest) {
				manifest.programs[0].dependencies = []captureProgramRef{{array: captureProgramArrayEnter, program: manifest.programs[0].programName}}
			},
			want: "dependency cycle",
		},
		{
			name: "duplicate route",
			edit: func(manifest *captureManifest) {
				manifest.routes = append(manifest.routes, manifest.routes[0])
			},
			want: "duplicate syscall route",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := newCaptureManifest()
			test.edit(&manifest)
			err := validateCaptureManifest(manifest)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validate error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestCaptureManifestRejectsUnknownDependency(t *testing.T) {
	manifest := newCaptureManifest()
	manifest.programs[0].dependencies = []captureProgramRef{{array: captureProgramArrayEnter, program: "missing"}}
	if err := validateCaptureManifest(manifest); err == nil || !strings.Contains(err.Error(), "unknown dependency program") {
		t.Fatalf("validate error = %v", err)
	}
}

func TestCaptureManifestWriteFailure(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full is unavailable")
	}
	if err := writeCaptureManifestFile("/dev/full", "capture manifest"); err == nil {
		t.Fatal("writeCaptureManifestFile succeeded on /dev/full")
	}
}
