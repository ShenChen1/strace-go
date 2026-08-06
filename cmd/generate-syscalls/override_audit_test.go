package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestWriteOverrideAuditPrintsRedundantNames(t *testing.T) {
	var out bytes.Buffer
	err := writeOverrideAudit(&out, fakeBTFSource{syscalls: map[string]SyscallMeta{
		"read":  {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		"write": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
	}}, map[string]SyscallMeta{
		"write": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		"read":  {Args: []string{"fd"}, ArgTypes: []string{"int"}},
	}, nil)
	if err != nil {
		t.Fatalf("writeOverrideAudit() error = %v", err)
	}
	if got, want := out.String(), "read\nwrite\n"; got != want {
		t.Fatalf("writeOverrideAudit() output = %q, want %q", got, want)
	}
}

func TestWriteOverrideAuditReportsSourceError(t *testing.T) {
	err := writeOverrideAudit(&bytes.Buffer{}, fakeBTFSource{err: errors.New("boom")}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "load BTF syscalls") {
		t.Fatalf("writeOverrideAudit() error = %v, want BTF context", err)
	}
}

func TestWriteOverrideAuditDetailPrintsStableRows(t *testing.T) {
	var out bytes.Buffer
	err := writeOverrideAuditDetail(&out, fakeBTFSource{syscalls: map[string]SyscallMeta{
		"key":   {Args: []string{"_type"}, ArgTypes: []string{"long unsigned int"}},
		"read":  {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		"stat":  {Args: []string{"filename", "statbuf"}, ArgTypes: []string{"const char *", "struct __old_kernel_stat *"}},
		"write": {Args: []string{"fd", "buffer"}, ArgTypes: []string{"unsigned int", "const char *"}},
	}}, map[string]SyscallMeta{
		"key":     {Args: []string{"type"}, ArgTypes: []string{"unsigned long"}},
		"stat":    {Args: []string{"filename", "statbuf"}, ArgTypes: []string{"const char *", "struct stat *"}},
		"write":   {Args: []string{"fd", "buf"}, ArgTypes: []string{"int", "const char *"}},
		"missing": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		"read":    {Args: []string{"fd"}, ArgTypes: []string{"int"}},
	}, nil)
	if err != nil {
		t.Fatalf("writeOverrideAuditDetail() error = %v", err)
	}
	want := strings.Join([]string{
		overrideAuditDetailHeader,
		"key\tnormalized_match\tnormalized_args,normalized_arg_types\ttype\tunsigned long\t_type\tlong unsigned int",
		"missing\tmissing_btf\tno_btf_metadata\tfd\tint\t\t",
		"read\tredundant\texact_signature\tfd\tint\tfd\tint",
		"stat\tsemantic_override\tstrace_stat_struct\tfilename,statbuf\tconst char *,struct stat *\tfilename,statbuf\tconst char *,struct __old_kernel_stat *",
		"write\tsignature_mismatch\targs,arg_types\tfd,buf\tint,const char *\tfd,buffer\tunsigned int,const char *",
		"",
	}, "\n")
	if got := out.String(); got != want {
		t.Fatalf("writeOverrideAuditDetail() output = %q, want %q", got, want)
	}
}

func TestWriteOverrideAuditDetailUsesDatasetSource(t *testing.T) {
	source := &fakeBTFDatasetSource{
		fakeBTFSource: fakeBTFSource{err: errors.New("LoadBTFSyscalls should not run")},
		dataset: btfSyscallDataset{
			Syscalls: map[string]SyscallMeta{
				"close": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
			},
			Diagnostics: map[string]btfSyscallDiagnostic{
				"missing": {Reason: btfDiagnosticPTRegsWrapperOnly},
			},
		},
	}
	overrides := map[string]SyscallMeta{
		"close":   {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		"missing": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
	}

	var out bytes.Buffer
	if err := writeOverrideAuditDetail(&out, source, overrides, nil); err != nil {
		t.Fatalf("writeOverrideAuditDetail() error = %v", err)
	}
	if source.datasetCalls != 1 {
		t.Fatalf("dataset calls = %d, want 1", source.datasetCalls)
	}
	got := out.String()
	if !strings.Contains(got, "close\tredundant\texact_signature") {
		t.Fatalf("output = %q, want close redundant row", got)
	}
	if !strings.Contains(got, "missing\tmissing_btf\tpt_regs_wrapper_only") {
		t.Fatalf("output = %q, want missing diagnostic row", got)
	}
}

func TestWriteOverrideAuditDetailReportsSourceError(t *testing.T) {
	err := writeOverrideAuditDetail(&bytes.Buffer{}, fakeBTFSource{err: errors.New("boom")}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "load BTF syscalls") {
		t.Fatalf("writeOverrideAuditDetail() error = %v, want BTF context", err)
	}
}

func TestWriteOverrideAuditDetailReportsDatasetError(t *testing.T) {
	err := writeOverrideAuditDetail(&bytes.Buffer{}, &fakeBTFDatasetSource{datasetErr: errors.New("boom")}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "load BTF syscall dataset") {
		t.Fatalf("writeOverrideAuditDetail() error = %v, want dataset context", err)
	}
}

func TestWriteOverrideAuditDetailReportsDiagnosticsError(t *testing.T) {
	err := writeOverrideAuditDetail(&bytes.Buffer{}, fakeBTFSource{diagErr: errors.New("boom")}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "load BTF syscall diagnostics") {
		t.Fatalf("writeOverrideAuditDetail() error = %v, want diagnostics context", err)
	}
}

func TestRedundantManualOverridesReportsExactSignatureMatches(t *testing.T) {
	overrides := map[string]SyscallMeta{
		"read":  {Name: "read", Args: []string{"fd", "buf"}, ArgTypes: []string{"int", "char *"}},
		"write": {Name: "write", Args: []string{"fd", "buf"}, ArgTypes: []string{"int", "const char *"}},
		"open":  {Name: "open", Args: []string{"path"}, ArgTypes: []string{"const char *"}},
	}
	btf := map[string]SyscallMeta{
		"read":  {Name: "read", Args: []string{"fd", "buf"}, ArgTypes: []string{"int", "char *"}},
		"write": {Name: "write", Args: []string{"fd", "buffer"}, ArgTypes: []string{"int", "const char *"}},
	}

	got := redundantManualOverrides(overrides, btf, nil)
	want := []string{"read"}
	if !sameStringSlice(got, want) {
		t.Fatalf("redundantManualOverrides() = %#v, want %#v", got, want)
	}
}

func TestOverrideAuditRowsClassifiesEveryOverride(t *testing.T) {
	overrides := map[string]SyscallMeta{
		"read":    {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		"write":   {Args: []string{"fd", "buf"}, ArgTypes: []string{"int", "const char *"}},
		"missing": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
	}
	btf := map[string]SyscallMeta{
		"read":  {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		"write": {Args: []string{"fd", "buffer"}, ArgTypes: []string{"int", "const char *"}},
	}

	got := overrideAuditRows(overrides, btf, nil, nil)
	if len(got) != 3 {
		t.Fatalf("overrideAuditRows() len = %d, want 3", len(got))
	}
	if got[0].Name != "missing" || got[0].Status != overrideAuditMissingBTF {
		t.Fatalf("row[0] = %#v, want missing_btf missing", got[0])
	}
	if got[1].Name != "read" || got[1].Status != overrideAuditRedundant {
		t.Fatalf("row[1] = %#v, want redundant read", got[1])
	}
	if got[2].Name != "write" || got[2].Status != overrideAuditSignatureMismatch || got[2].Reason != "args" {
		t.Fatalf("row[2] = %#v, want args mismatch write", got[2])
	}
}

func TestOverrideAuditRowsReportsNormalizedMatches(t *testing.T) {
	overrides := map[string]SyscallMeta{
		"brk":     {Args: []string{"brk"}, ArgTypes: []string{"unsigned long"}},
		"add_key": {Args: []string{"type"}, ArgTypes: []string{"const char *"}},
	}
	btf := map[string]SyscallMeta{
		"brk":     {Args: []string{"brk"}, ArgTypes: []string{"long unsigned int"}},
		"add_key": {Args: []string{"_type"}, ArgTypes: []string{"const char *"}},
	}

	got := overrideAuditRows(overrides, btf, nil, nil)
	if got[0].Name != "add_key" || got[0].Status != overrideAuditNormalizedMatch || got[0].Reason != "normalized_args" {
		t.Fatalf("row[0] = %#v, want normalized args add_key", got[0])
	}
	if got[1].Name != "brk" || got[1].Status != overrideAuditNormalizedMatch || got[1].Reason != "normalized_arg_types" {
		t.Fatalf("row[1] = %#v, want normalized arg types brk", got[1])
	}
}

func TestOverrideAuditRowsClassifiesSemanticOverrides(t *testing.T) {
	overrides := map[string]SyscallMeta{
		"stat":  {Args: []string{"filename", "statbuf"}, ArgTypes: []string{"const char *", "struct stat *"}},
		"write": {Args: []string{"fd", "buf"}, ArgTypes: []string{"int", "char *"}},
	}
	btf := map[string]SyscallMeta{
		"stat":  {Args: []string{"filename", "statbuf"}, ArgTypes: []string{"const char *", "struct __old_kernel_stat *"}},
		"write": {Args: []string{"fd", "buffer"}, ArgTypes: []string{"int", "char *"}},
	}

	got := overrideAuditRows(overrides, btf, nil, nil)
	if got[0].Name != "stat" || got[0].Status != overrideAuditSemanticOverride || got[0].Reason != "strace_stat_struct" {
		t.Fatalf("row[0] = %#v, want semantic override stat", got[0])
	}
	if got[1].Name != "write" || got[1].Status != overrideAuditSignatureMismatch || got[1].Reason != "args" {
		t.Fatalf("row[1] = %#v, want signature mismatch write", got[1])
	}
}

func TestOverrideAuditRowsUsesBTFAliases(t *testing.T) {
	overrides := map[string]SyscallMeta{
		"mmap": {
			Args:     []string{"addr", "len", "prot", "flags", "fd", "off"},
			ArgTypes: []string{"const void *", "size_t", "unsigned long", "unsigned long", "int", "kernel_off_t"},
		},
	}
	btf := map[string]SyscallMeta{
		"mmap_pgoff": {
			Args:     []string{"addr", "len", "prot", "flags", "fd", "pgoff"},
			ArgTypes: []string{"long unsigned int", "long unsigned int", "long unsigned int", "long unsigned int", "long unsigned int", "long unsigned int"},
		},
	}
	aliases := map[string]string{"mmap_pgoff": "mmap"}

	got := overrideAuditRows(overrides, btf, aliases, nil)
	if got[0].Name != "mmap" || got[0].Status != overrideAuditSemanticOverride || got[0].Reason != "strace_mmap_signature" {
		t.Fatalf("row[0] = %#v, want aliased semantic override mmap", got[0])
	}
}

func TestOverrideAuditRowsClassifiesInternalSocketSignatures(t *testing.T) {
	overrides := map[string]SyscallMeta{
		"getsockname": {
			Args:     []string{"fd", "usockaddr", "usockaddr_len"},
			ArgTypes: []string{"int", "struct sockaddr *", "int *"},
		},
	}
	btf := map[string]SyscallMeta{
		"getsockname": {
			Args:     []string{"fd", "usockaddr", "usockaddr_len", "peer"},
			ArgTypes: []string{"int", "struct sockaddr *", "int *", "int"},
		},
	}

	got := overrideAuditRows(overrides, btf, nil, nil)
	if got[0].Name != "getsockname" || got[0].Status != overrideAuditSemanticOverride || got[0].Reason != "strace_socket_signature" {
		t.Fatalf("row[0] = %#v, want socket semantic override getsockname", got[0])
	}
}

func TestOverrideAuditRowsClassifiesBpfSignature(t *testing.T) {
	overrides := map[string]SyscallMeta{
		"bpf": {
			Args:     []string{"cmd", "attr", "size"},
			ArgTypes: []string{"int", "void *", "unsigned int"},
		},
	}
	btf := map[string]SyscallMeta{
		"bpf": {
			Args:     []string{"cmd", "uattr", "size"},
			ArgTypes: []string{"enum bpf_cmd", "bpfptr_t", "unsigned int"},
		},
	}

	got := overrideAuditRows(overrides, btf, nil, nil)
	if got[0].Name != "bpf" || got[0].Status != overrideAuditSemanticOverride || got[0].Reason != "strace_bpf_attr_signature" {
		t.Fatalf("row[0] = %#v, want bpf semantic override", got[0])
	}
}

func TestOverrideAuditRowsReportsWrapperOnlyMissingBTF(t *testing.T) {
	overrides := map[string]SyscallMeta{
		"close": {
			Args:     []string{"fd"},
			ArgTypes: []string{"int"},
		},
	}
	diagnostics := map[string]btfSyscallDiagnostic{
		"close": {
			Function: "__x64_sys_close",
			Reason:   btfDiagnosticPTRegsWrapperOnly,
		},
	}

	got := overrideAuditRows(overrides, nil, nil, diagnostics)
	if got[0].Name != "close" || got[0].Status != overrideAuditMissingBTF || got[0].Reason != btfDiagnosticPTRegsWrapperOnly {
		t.Fatalf("row[0] = %#v, want pt_regs wrapper missing BTF", got[0])
	}
}

func TestOverrideAuditRowsUsesBTFAliasesForDiagnostics(t *testing.T) {
	overrides := map[string]SyscallMeta{
		"umount2": {
			Args:     []string{"target", "flags"},
			ArgTypes: []string{"const char *", "int"},
		},
	}
	diagnostics := map[string]btfSyscallDiagnostic{
		"umount": {
			Function: "__x64_sys_umount",
			Reason:   btfDiagnosticPTRegsWrapperOnly,
		},
	}
	aliases := map[string]string{"umount": "umount2"}

	got := overrideAuditRows(overrides, nil, aliases, diagnostics)
	if got[0].Name != "umount2" || got[0].Status != overrideAuditMissingBTF || got[0].Reason != btfDiagnosticPTRegsWrapperOnly {
		t.Fatalf("row[0] = %#v, want aliased pt_regs wrapper missing BTF", got[0])
	}
}

func TestRedundantManualOverridesSortsNames(t *testing.T) {
	overrides := map[string]SyscallMeta{
		"write": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		"read":  {Args: []string{"fd"}, ArgTypes: []string{"int"}},
	}
	btf := map[string]SyscallMeta{
		"write": {Args: []string{"fd"}, ArgTypes: []string{"int"}},
		"read":  {Args: []string{"fd"}, ArgTypes: []string{"int"}},
	}

	got := redundantManualOverrides(overrides, btf, nil)
	want := []string{"read", "write"}
	if !sameStringSlice(got, want) {
		t.Fatalf("redundantManualOverrides() = %#v, want %#v", got, want)
	}
}
