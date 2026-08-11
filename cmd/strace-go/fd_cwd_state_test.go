package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"strace-go/pkg/meta"
)

func TestFDStateCwdUpdatesFromChdirPath(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:cwd": "/work/base"}, nil)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, ret: 0},
		statePID: 101,
		meta:     meta.Syscall{Name: "chdir"},
		pathText: `"nested/../child"`,
	}
	ev.updateFDState(store)

	if got, ok := store.Cwd(101); !ok || got != "/work/base/child" {
		t.Fatalf("cwd = %q, %v; want /work/base/child", got, ok)
	}
}

func TestFDStateCwdUpdatesFromFchdirFD(t *testing.T) {
	store := newFDStateStoreFromMaps(map[string]string{"101:7": "/mnt/work"}, nil)
	ev := syscallEventContext{
		view:     syscallEventView{valid: true, args: [6]uint64{7}, ret: 0},
		statePID: 101,
		meta:     meta.Syscall{Name: "fchdir"},
	}
	ev.updateFDState(store)

	if got, ok := store.Cwd(101); !ok || got != "/mnt/work" {
		t.Fatalf("cwd = %q, %v; want /mnt/work", got, ok)
	}
}

func TestFDStateCwdIgnoresFailedOrUnusableChdir(t *testing.T) {
	for _, test := range []struct {
		name     string
		ret      int64
		pathText string
	}{
		{name: "failed", ret: -2, pathText: `"/new"`},
		{name: "pointer", ret: 0, pathText: "0x1000"},
		{name: "null", ret: 0, pathText: "NULL"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newFDStateStoreFromMaps(map[string]string{"101:cwd": "/old"}, nil)
			ev := syscallEventContext{
				view:     syscallEventView{valid: true, ret: test.ret},
				statePID: 101,
				meta:     meta.Syscall{Name: "chdir"},
				pathText: test.pathText,
			}
			ev.updateFDState(store)
			if got, ok := store.Cwd(101); !ok || got != "/old" {
				t.Fatalf("cwd = %q, %v; want unchanged /old", got, ok)
			}
		})
	}
}

func TestCwdMutationDoesNotUseHandlerMapAPI(t *testing.T) {
	root := repositoryRoot(t)
	paths, err := filepath.Glob(filepath.Join(root, "pkg", "handler", "*.go"))
	if err != nil {
		t.Fatalf("glob handler sources: %v", err)
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		source := string(data)
		if strings.Contains(source, "func UpdateCwd(") || strings.Contains(source, "func UpdateCwdByFd(") {
			t.Fatalf("handler source %s exposes CWD map mutation", path)
		}
	}
	eventUtils, err := os.ReadFile(filepath.Join(root, "cmd", "strace-go", "event_utils.go"))
	if err != nil {
		t.Fatalf("read event_utils.go: %v", err)
	}
	if strings.Contains(string(eventUtils), "handler.UpdateCwd") {
		t.Fatal("event_utils.go still calls handler CWD mutation API")
	}
}
