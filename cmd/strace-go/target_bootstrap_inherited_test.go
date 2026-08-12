package main

import (
	"errors"
	"os"
	"testing"
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
