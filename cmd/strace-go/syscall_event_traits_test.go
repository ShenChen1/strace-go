package main

import "testing"

func TestSyscallEventTraitsUseSyscallID(t *testing.T) {
	tests := []struct {
		name  string
		flags syscallEventTraits
	}{
		{name: "getpid"},
		{name: "openat", flags: syscallEventTraitHandler | syscallEventTraitState | syscallEventTraitOffset},
		{name: "read", flags: syscallEventTraitStateIO | syscallEventTraitOffsetIO},
		{name: "write", flags: syscallEventTraitStateIO | syscallEventTraitOffsetIO},
		{name: "close", flags: syscallEventTraitHandler | syscallEventTraitClose},
		{name: "eventfd2", flags: syscallEventTraitHandler | syscallEventTraitState | syscallEventTraitOffset | syscallEventTraitCreator},
		{name: "exit_group", flags: syscallEventTraitExit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			view := syscallEventView{sysID: syscallIDByName(t, tt.name)}
			if got := syscallEventTraitsForView(view, tt.name); got != tt.flags {
				t.Fatalf("traits for %s = %#x, want %#x", tt.name, got, tt.flags)
			}
		})
	}
}

func TestSyscallEventTraitsKeepSyntheticNameFallback(t *testing.T) {
	view := syscallEventView{sysID: 0}
	got := syscallEventTraitsForView(view, "openat")
	want := syscallEventTraitHandler | syscallEventTraitState | syscallEventTraitOffset
	if got != want {
		t.Fatalf("synthetic traits = %#x, want %#x", got, want)
	}
}

func TestSyntheticReadDoesNotAssumeSyscallZero(t *testing.T) {
	want := syscallEventTraitStateIO | syscallEventTraitOffsetIO
	if got := syscallEventTraitsForView(syscallEventView{}, "read"); got != want {
		t.Fatalf("synthetic read traits = %#x, want %#x", got, want)
	}
}
