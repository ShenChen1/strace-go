package main

import (
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestCollectBTFSyscallsPrefersTracepointStruct(t *testing.T) {
	got := collectBTFSyscalls([]btf.Type{
		&btf.Func{
			Name: "__do_sys_openat",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "function_dfd", Type: &btf.Int{Name: "int"}},
				{Name: "function_path", Type: &btf.Pointer{Target: &btf.Int{Name: "char"}}},
			}},
		},
		&btf.Struct{
			Name: "trace_event_raw_sys_enter_openat",
			Members: []btf.Member{
				{Name: "ent", Type: &btf.Struct{Name: "trace_entry"}},
				{Name: "dfd", Type: &btf.Int{Name: "int"}},
				{Name: "filename", Type: &btf.Pointer{Target: &btf.Const{Type: &btf.Int{Name: "char"}}}},
			},
		},
	})

	assertMeta(t, got["openat"], SyscallMeta{
		Name:     "openat",
		Args:     []string{"dfd", "filename"},
		ArgTypes: []string{"int", "const char *"},
	})
}

func TestCollectBTFSyscallsFallsBackToFunctionBTF(t *testing.T) {
	got := collectBTFSyscalls([]btf.Type{
		&btf.Func{
			Name: "__x64_sys_read",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "fd", Type: &btf.Int{Name: "unsigned int"}},
			}},
		},
		&btf.Func{
			Name: "__do_sys_read",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "fd", Type: &btf.Int{Name: "unsigned int"}},
				{Name: "buf", Type: &btf.Pointer{Target: &btf.Int{Name: "char"}}},
			}},
		},
	})

	assertMeta(t, got["read"], SyscallMeta{
		Name:     "read",
		Args:     []string{"fd", "buf"},
		ArgTypes: []string{"unsigned int", "char *"},
	})
}

func TestCollectBTFSyscallsAllowsInternalSocketFuncs(t *testing.T) {
	got := collectBTFSyscalls([]btf.Type{
		&btf.Func{
			Name: "__sys_connect",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "fd", Type: &btf.Int{Name: "unsigned int"}},
				{Name: "uservaddr", Type: &btf.Pointer{Target: &btf.Struct{Name: "sockaddr"}}},
				{Name: "addrlen", Type: &btf.Int{Name: "unsigned int"}},
			}},
		},
		&btf.Func{
			Name: "__sys_setuid",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "uid", Type: &btf.Int{Name: "uid_t"}},
			}},
		},
	})

	assertMeta(t, got["connect"], SyscallMeta{
		Name:     "connect",
		Args:     []string{"fd", "uservaddr", "addrlen"},
		ArgTypes: []string{"unsigned int", "struct sockaddr *", "unsigned int"},
	})
	if _, ok := got["setuid"]; ok {
		t.Fatal("collectBTFSyscalls() collected __sys_setuid, want allowlist rejection")
	}
}

func TestCollectBTFSyscallsAllowsInternalBpfFunc(t *testing.T) {
	got := collectBTFSyscalls([]btf.Type{
		&btf.Func{
			Name: "__sys_bpf",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "cmd", Type: &btf.Enum{Name: "bpf_cmd"}},
				{Name: "uattr", Type: &btf.Typedef{Name: "bpfptr_t", Type: &btf.Pointer{Target: &btf.Union{Name: "bpf_attr"}}}},
				{Name: "size", Type: &btf.Int{Name: "unsigned int"}},
			}},
		},
	})

	assertMeta(t, got["bpf"], SyscallMeta{
		Name:     "bpf",
		Args:     []string{"cmd", "uattr", "size"},
		ArgTypes: []string{"enum bpf_cmd", "bpfptr_t", "unsigned int"},
	})
}

func TestCollectBTFSyscallDiagnosticsReportsWrapperOnlyFuncs(t *testing.T) {
	types := []btf.Type{
		&btf.Func{
			Name: "__x64_sys_close",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "regs", Type: &btf.Pointer{Target: &btf.Struct{Name: "pt_regs"}}},
			}},
		},
		&btf.Func{
			Name: "__x64_sys_read",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "regs", Type: &btf.Pointer{Target: &btf.Struct{Name: "pt_regs"}}},
			}},
		},
		&btf.Func{
			Name: "__do_sys_read",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "fd", Type: &btf.Int{Name: "unsigned int"}},
				{Name: "buf", Type: &btf.Pointer{Target: &btf.Int{Name: "char"}}},
			}},
		},
		&btf.Func{
			Name: "__sys_setuid",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "uid", Type: &btf.Int{Name: "uid_t"}},
			}},
		},
	}
	got := collectBTFSyscallDiagnostics(types, collectBTFSyscalls(types))

	if got["close"].Function != "__x64_sys_close" || got["close"].Reason != btfDiagnosticPTRegsWrapperOnly {
		t.Fatalf("diagnostic close = %#v, want pt_regs wrapper", got["close"])
	}
	if _, ok := got["read"]; ok {
		t.Fatalf("diagnostic read = %#v, want omitted because __do_sys_read is usable", got["read"])
	}
	if _, ok := got["setuid"]; ok {
		t.Fatalf("diagnostic setuid = %#v, want omitted because __sys_setuid is not allowlisted", got["setuid"])
	}
}

func TestCollectBTFSyscallDatasetReturnsSyscallsAndDiagnostics(t *testing.T) {
	got := collectBTFSyscallDataset([]btf.Type{
		&btf.Func{
			Name: "__x64_sys_close",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "regs", Type: &btf.Pointer{Target: &btf.Struct{Name: "pt_regs"}}},
			}},
		},
		&btf.Func{
			Name: "__do_sys_read",
			Type: &btf.FuncProto{Params: []btf.FuncParam{
				{Name: "fd", Type: &btf.Int{Name: "unsigned int"}},
				{Name: "buf", Type: &btf.Pointer{Target: &btf.Int{Name: "char"}}},
			}},
		},
	})

	assertMeta(t, got.Syscalls["read"], SyscallMeta{
		Name:     "read",
		Args:     []string{"fd", "buf"},
		ArgTypes: []string{"unsigned int", "char *"},
	})
	if got.Diagnostics["close"].Reason != btfDiagnosticPTRegsWrapperOnly {
		t.Fatalf("diagnostic close = %#v, want pt_regs wrapper", got.Diagnostics["close"])
	}
}

func TestSyscallMetaFromTracepointStruct(t *testing.T) {
	meta, ok := syscallMetaFromTracepointStruct(&btf.Struct{
		Name: "trace_event_raw_sys_enter_openat",
		Members: []btf.Member{
			{Name: "ent", Type: &btf.Struct{Name: "trace_entry"}},
			{Name: "__syscall_nr", Type: &btf.Int{Name: "long int"}},
			{Name: "dfd", Type: &btf.Int{Name: "int"}},
			{Name: "filename", Type: &btf.Pointer{Target: &btf.Const{Type: &btf.Int{Name: "char"}}}},
			{Name: "flags", Type: &btf.Int{Name: "int"}},
			{Name: "mode", Type: &btf.Typedef{Name: "umode_t", Type: &btf.Int{Name: "unsigned short"}}},
			{Name: "__data", Type: &btf.Array{Type: &btf.Int{Name: "char"}}},
		},
	})
	if !ok {
		t.Fatal("syscallMetaFromTracepointStruct() ok = false, want true")
	}
	want := SyscallMeta{
		Name:     "openat",
		Args:     []string{"dfd", "filename", "flags", "mode"},
		ArgTypes: []string{"int", "const char *", "int", "umode_t"},
	}
	assertMeta(t, meta, want)
}

func TestSyscallMetaFromTracepointStructRejectsNonSyscallStruct(t *testing.T) {
	tests := []*btf.Struct{
		{Name: "trace_event_raw_sys_enter"},
		{Name: "trace_event_raw_sys_exit_openat"},
		{Name: "trace_event_raw_sys_enter_openat", Members: []btf.Member{{Name: "ent"}}},
	}
	for _, st := range tests {
		t.Run(st.Name, func(t *testing.T) {
			if meta, ok := syscallMetaFromTracepointStruct(st); ok {
				t.Fatalf("syscallMetaFromTracepointStruct() = %#v, want rejected", meta)
			}
		})
	}
}

func TestSyscallNameFromBTFFunc(t *testing.T) {
	tests := []struct {
		name string
		want string
		ok   bool
	}{
		{name: "__x64_sys_openat", want: "openat", ok: true},
		{name: "__do_sys_read", want: "read", ok: true},
		{name: "__sys_connect", want: "connect", ok: true},
		{name: "__sys_setuid", ok: false},
		{name: "ksys_write", want: "write", ok: true},
		{name: "helper_sys_read", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := syscallNameFromBTFFunc(tt.name)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("syscallNameFromBTFFunc() = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestShouldUseBTFCandidate(t *testing.T) {
	existing := SyscallMeta{Name: "openat", Args: []string{"dfd", "filename"}}
	tests := []struct {
		name          string
		candidateFunc string
		candidateArgc int
		want          bool
	}{
		{name: "shorter candidate loses", candidateFunc: "__do_sys_openat", candidateArgc: 1, want: false},
		{name: "longer candidate wins", candidateFunc: "__x64_sys_openat", candidateArgc: 3, want: true},
		{name: "same length do_sys wins", candidateFunc: "__do_sys_openat", candidateArgc: 2, want: true},
		{name: "same length non do_sys loses", candidateFunc: "__x64_sys_openat", candidateArgc: 2, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldUseBTFCandidate(existing, tt.candidateFunc, tt.candidateArgc); got != tt.want {
				t.Fatalf("shouldUseBTFCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}
