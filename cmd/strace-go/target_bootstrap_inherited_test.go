package main

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCollectInheritedFilesFromFDsPreservesFDSlots(t *testing.T) {
	created := make([]*os.File, 0, 2)
	files, err := collectInheritedFilesFromFDs([]int{3, 5}, func(fd int) (*os.File, error) {
		file, err := os.CreateTemp(t.TempDir(), "inherited-slot-")
		if err != nil {
			return nil, err
		}
		created = append(created, file)
		return file, nil
	})
	if err != nil {
		t.Fatalf("collectInheritedFilesFromFDs() error = %v", err)
	}
	defer closeFiles(files)
	if len(files) != 3 || files[0] != created[0] || files[1] != nil || files[2] != created[1] {
		t.Fatalf("inherited files = %#v, want fd 3/5 slots", files)
	}
}

func TestCollectInheritedFilesFromFDsCleansPartialDuplicates(t *testing.T) {
	wantErr := errors.New("duplicate failed")
	var first *os.File
	files, err := collectInheritedFilesFromFDs([]int{3, 4}, func(fd int) (*os.File, error) {
		if fd == 4 {
			return nil, wantErr
		}
		var err error
		first, err = os.CreateTemp(t.TempDir(), "inherited-partial-")
		return first, err
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("collectInheritedFilesFromFDs() error = %v, want %v", err, wantErr)
	}
	if files != nil {
		t.Fatalf("partial inherited files = %#v, want nil", files)
	}
	if _, err := first.Write([]byte("closed")); err == nil {
		t.Fatal("partial duplicate remained open after collection failure")
	}
}

func TestCollectInheritedFilesFromFDsRejectsNilAndEmptyInputs(t *testing.T) {
	files, err := collectInheritedFilesFromFDs(nil, nil)
	if err != nil || files != nil {
		t.Fatalf("empty collection = files:%v err:%v, want nil/nil", files, err)
	}
	_, err = collectInheritedFilesFromFDs([]int{3}, nil)
	if err == nil {
		t.Fatal("nil duplicator returned nil error")
	}
}

func TestIsPassThroughFDTreatsClosedDescriptorAsRace(t *testing.T) {
	pass, err := isPassThroughFD(-1)
	if err != nil {
		t.Fatalf("isPassThroughFD(-1) error = %v, want nil for EBADF race", err)
	}
	if pass {
		t.Fatal("isPassThroughFD(-1) = true, want false")
	}
}

func TestNewTraceCommandPreservesSparseExtraFileSlots(t *testing.T) {
	if os.Getenv("STRACE_GO_EXTRA_FILE_HELPER") == "1" {
		verifySparseExtraFileSlots(t)
		return
	}

	first, err := os.CreateTemp(t.TempDir(), "extra-file-first-")
	if err != nil {
		t.Fatalf("create first extra file: %v", err)
	}
	defer first.Close()
	second, err := os.CreateTemp(t.TempDir(), "extra-file-second-")
	if err != nil {
		t.Fatalf("create second extra file: %v", err)
	}
	defer second.Close()

	cmd := newTraceCommand(traceCommandSpec{
		args:       []string{os.Args[0], "-test.run=TestNewTraceCommandPreservesSparseExtraFileSlots"},
		envActions: []string{"STRACE_GO_EXTRA_FILE_HELPER=1"},
	}, []*os.File{first, nil, second})
	if err := cmd.Run(); err != nil {
		t.Fatalf("sparse ExtraFiles helper failed: %v", err)
	}

	assertFileContents(t, first, "fd3")
	assertFileContents(t, second, "fd5")
}

func verifySparseExtraFileSlots(t *testing.T) {
	for _, fd := range []int{3, 5} {
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			t.Fatalf("Fstat(%d) error = %v, want inherited file", fd, err)
		}
	}
	var stat unix.Stat_t
	if err := unix.Fstat(4, &stat); !errors.Is(err, unix.EBADF) {
		t.Fatalf("Fstat(4) error = %v, want EBADF for nil ExtraFiles slot", err)
	}
	for _, item := range []struct {
		fd   int
		data string
	}{
		{fd: 3, data: "fd3"},
		{fd: 5, data: "fd5"},
	} {
		written, err := unix.Write(item.fd, []byte(item.data))
		if err != nil || written != len(item.data) {
			t.Fatalf("write fd %d = (%d, %v), want %d bytes", item.fd, written, err, len(item.data))
		}
	}
}

func assertFileContents(t *testing.T, file *os.File, want string) {
	t.Helper()
	data := make([]byte, len(want))
	if _, err := file.ReadAt(data, 0); err != nil {
		t.Fatalf("read inherited file %s: %v", file.Name(), err)
	}
	if string(data) != want {
		t.Fatalf("inherited file %s = %q, want %q", file.Name(), data, want)
	}
}
