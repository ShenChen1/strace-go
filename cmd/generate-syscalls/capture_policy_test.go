package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCapturePolicy(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [openat]
    enter:
      reads:
        - { arg: 1, size: 4096, type: string }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err != nil {
		t.Fatalf("loadCapturePolicy() error = %v", err)
	}
	if got := len(globalConfig.Rules); got != 1 {
		t.Fatalf("rules = %d, want 1", got)
	}
	rule := globalConfig.Rules[0]
	if len(rule.Syscalls) != 1 || rule.Syscalls[0] != "openat" {
		t.Fatalf("syscalls = %#v, want [openat]", rule.Syscalls)
	}
	if len(rule.Enter.Reads) != 1 || rule.Enter.Reads[0].Type != "string" {
		t.Fatalf("enter reads = %#v, want one string read", rule.Enter.Reads)
	}
}

func TestLoadCapturePolicyNormalizesPayloads(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [write]
    enter:
      payloads:
        - { arg: 1, kind: bytes, direction: in, len_from_arg: 2, max: 512, offset: 0 }
  - syscalls: [openat]
    enter:
      payloads:
        - { arg: 1, kind: string, direction: in, max: 4096 }
  - syscalls: [readv]
    enter:
      payloads:
        - { arg: 1, kind: iovec, direction: in, count_from_arg: 2, elem_size: 16, max: 512 }
  - syscalls: [epoll_wait]
    exit:
      payloads:
        - { arg: 1, kind: struct, direction: out, count_from_ret: true, elem_size: 12, max: 512 }
  - syscalls: [openat2]
    enter:
      payloads:
        - { arg: 2, kind: struct, direction: in, len_from_arg: 3, min: 24, max: 64 }
  - syscalls: [accept]
    exit:
      payloads:
        - { arg: 1, kind: struct, direction: out, len_from_user_arg: 2, clamp_u32_from_offset: 768, max: 128 }
  - syscalls: [ioctl]
    enter:
      payloads:
        - { arg: 2, kind: raw, direction: in, len_from_arg_bits: { arg: 1, shift: 16, mask: 16383, zero_len: 128 }, max: 512, offset: 512 }
  - syscalls: [io_getevents]
    enter:
      payloads:
        - { arg: 5, kind: double_ptr, direction: in, size: 8, offset: 544 }
  - syscalls: [fcntl]
    enter:
      payloads:
        - { arg: 2, kind: raw, direction: in, len_from_arg_cases: { arg: 1, cases: [{ size: 8, values: [15, 16] }, { size: 32, values: [5, 6] }] }, max: 32 }
  - syscalls: [futex_waitv]
    enter:
      payloads:
        - { arg: 0, kind: raw, direction: in, count_from_arg: 1, elem_size: 24, max: 3072, split_first: 24 }
  - syscalls: [fsconfig]
    enter:
      payloads:
        - { arg: 3, kind: string_or_bytes, direction: in, string_bytes_switch: { selector_arg: 1, bytes_value: 2, len_from_arg: 4, len_mask: 8191 }, max: 4096, offset: 257 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err != nil {
		t.Fatalf("loadCapturePolicy() error = %v", err)
	}
	writeRead := globalConfig.Rules[0].Enter.Reads[0]
	if writeRead.Arg != 1 || writeRead.Size != 0 || writeRead.Offset != 0 || writeRead.Type != "raw" {
		t.Fatalf("write payload normalized to %#v, want arg 1 dynamic raw read", writeRead)
	}
	if writeRead.LenFromArg == nil || *writeRead.LenFromArg != 2 || writeRead.Max != 512 {
		t.Fatalf("write dynamic policy = %#v, want len_from_arg 2 max 512", writeRead)
	}
	openRead := globalConfig.Rules[1].Enter.Reads[0]
	if openRead.Arg != 1 || openRead.Size != 4096 || openRead.Offset != 0 || openRead.Type != "string" {
		t.Fatalf("string payload normalized to %#v, want fixed string read", openRead)
	}
	iovecRead := globalConfig.Rules[2].Enter.Reads[0]
	if iovecRead.Arg != 1 || iovecRead.Size != 0 || iovecRead.Type != "raw" {
		t.Fatalf("iovec payload normalized to %#v, want arg 1 dynamic raw read", iovecRead)
	}
	if iovecRead.CountFromArg == nil || *iovecRead.CountFromArg != 2 || iovecRead.ElemSize != 16 || iovecRead.Max != 512 {
		t.Fatalf("iovec dynamic policy = %#v, want count_from_arg 2 elem_size 16 max 512", iovecRead)
	}
	epollRead := globalConfig.Rules[3].Exit.Reads[0]
	if epollRead.Arg != 1 || epollRead.Size != 0 || epollRead.Type != "raw" {
		t.Fatalf("epoll payload normalized to %#v, want arg 1 dynamic raw read", epollRead)
	}
	if !epollRead.CountFromRet || epollRead.ElemSize != 12 || epollRead.Max != 512 {
		t.Fatalf("epoll dynamic policy = %#v, want count_from_ret elem_size 12 max 512", epollRead)
	}
	openat2Read := globalConfig.Rules[4].Enter.Reads[0]
	if openat2Read.LenFromArg == nil || *openat2Read.LenFromArg != 3 || openat2Read.Min != 24 || openat2Read.Max != 64 {
		t.Fatalf("openat2 dynamic policy = %#v, want len_from_arg 3 min 24 max 64", openat2Read)
	}
	acceptRead := globalConfig.Rules[5].Exit.Reads[0]
	if acceptRead.Arg != 1 || acceptRead.Size != 0 || acceptRead.Type != "raw" {
		t.Fatalf("accept payload normalized to %#v, want dynamic raw read", acceptRead)
	}
	if acceptRead.LenFromUserArg == nil || *acceptRead.LenFromUserArg != 2 || acceptRead.ClampU32FromOffset == nil || *acceptRead.ClampU32FromOffset != 768 || acceptRead.Max != 128 {
		t.Fatalf("accept dynamic policy = %#v, want len_from_user_arg 2 clamp offset 768 max 128", acceptRead)
	}
	ioctlRead := globalConfig.Rules[6].Enter.Reads[0]
	if ioctlRead.Arg != 2 || ioctlRead.Size != 0 || ioctlRead.Type != "raw" || ioctlRead.Offset != 512 {
		t.Fatalf("ioctl payload normalized to %#v, want arg 2 dynamic raw read at offset 512", ioctlRead)
	}
	if ioctlRead.LenFromArgBits == nil || ioctlRead.LenFromArgBits.Arg != 1 || ioctlRead.LenFromArgBits.Shift != 16 || ioctlRead.LenFromArgBits.Mask != 16383 || ioctlRead.LenFromArgBits.ZeroLen != 128 || ioctlRead.Max != 512 {
		t.Fatalf("ioctl dynamic policy = %#v, want ioctl bitfield length policy", ioctlRead)
	}
	ioGeteventsRead := globalConfig.Rules[7].Enter.Reads[0]
	if ioGeteventsRead.Arg != 5 || ioGeteventsRead.Size != 8 || ioGeteventsRead.Offset != 544 || ioGeteventsRead.Type != "double_ptr" {
		t.Fatalf("io_getevents payload normalized to %#v, want fixed double_ptr read", ioGeteventsRead)
	}
	fcntlRead := globalConfig.Rules[8].Enter.Reads[0]
	if fcntlRead.Arg != 2 || fcntlRead.Size != 0 || fcntlRead.Type != "raw" {
		t.Fatalf("fcntl payload normalized to %#v, want arg 2 dynamic raw read", fcntlRead)
	}
	if fcntlRead.LenFromArgCases == nil || fcntlRead.LenFromArgCases.Arg != 1 || fcntlRead.Max != 32 {
		t.Fatalf("fcntl dynamic policy = %#v, want len_from_arg_cases arg 1 max 32", fcntlRead)
	}
	if got := len(fcntlRead.LenFromArgCases.Cases); got != 2 {
		t.Fatalf("fcntl cases = %d, want 2", got)
	}
	futexWaitvRead := globalConfig.Rules[9].Enter.Reads[0]
	if futexWaitvRead.Arg != 0 || futexWaitvRead.Size != 0 || futexWaitvRead.Type != "raw" {
		t.Fatalf("futex_waitv payload normalized to %#v, want dynamic raw read", futexWaitvRead)
	}
	if futexWaitvRead.CountFromArg == nil || *futexWaitvRead.CountFromArg != 1 || futexWaitvRead.ElemSize != 24 || futexWaitvRead.Max != 3072 || futexWaitvRead.SplitFirst != 24 {
		t.Fatalf("futex_waitv dynamic policy = %#v, want count_from_arg split read", futexWaitvRead)
	}
	fsconfigRead := globalConfig.Rules[10].Enter.Reads[0]
	if fsconfigRead.Arg != 3 || fsconfigRead.Size != 0 || fsconfigRead.Type != "raw" || fsconfigRead.Offset != 257 || fsconfigRead.Max != 4096 {
		t.Fatalf("fsconfig payload normalized to %#v, want switched string/bytes read", fsconfigRead)
	}
	if fsconfigRead.StringBytesSwitch == nil || fsconfigRead.StringBytesSwitch.SelectorArg != 1 || fsconfigRead.StringBytesSwitch.BytesValue != 2 || fsconfigRead.StringBytesSwitch.LenFromArg != 4 || fsconfigRead.StringBytesSwitch.LenMask != 8191 {
		t.Fatalf("fsconfig switch policy = %#v, want selector arg 1 bytes value 2 len arg 4 mask 8191", fsconfigRead.StringBytesSwitch)
	}
}

func TestLoadCapturePolicyRejectsMixedReadsAndPayloads(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()
	globalConfig = Config{Rules: []CaptureRule{{Syscalls: []string{"sentinel"}}}}

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [write]
    enter:
      reads:
        - { arg: 1, size: 0, type: raw }
      payloads:
        - { arg: 1, kind: bytes, direction: in, len_from_arg: 2, max: 512 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want mixed reads/payloads error")
	}
	if got := globalConfig.Rules[0].Syscalls[0]; got != "sentinel" {
		t.Fatalf("globalConfig mutated after load error: got %q", got)
	}
}

func TestLoadCapturePolicyRejectsInvalidPayload(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [write]
    enter:
      payloads:
        - { arg: 1, kind: mystery, direction: in, max: 512 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want invalid kind error")
	}
}

func TestLoadCapturePolicyRejectsInvalidDynamicLength(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [read]
    exit:
      payloads:
        - { arg: 1, kind: bytes, direction: out, len_from_arg: 2, len_from_ret: true, max: 512 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want invalid dynamic length error")
	}
}

func TestLoadCapturePolicyRequiresDynamicMax(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [read]
    exit:
      payloads:
        - { arg: 1, kind: bytes, direction: out, len_from_ret: true }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want missing dynamic max error")
	}
}

func TestLoadCapturePolicyRequiresElementSizeForCount(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [readv]
    enter:
      payloads:
        - { arg: 1, kind: iovec, direction: in, count_from_arg: 2, max: 512 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want missing elem_size error")
	}
}

func TestLoadCapturePolicyRejectsInvalidSplitFirst(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [futex_waitv]
    enter:
      payloads:
        - { arg: 0, kind: raw, direction: in, len_from_arg: 1, max: 512, split_first: 24 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want split_first without count_from_arg error")
	}
}

func TestLoadCapturePolicyRejectsSplitFirstWithTooSmallMax(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [futex_waitv]
    enter:
      payloads:
        - { arg: 0, kind: raw, direction: in, count_from_arg: 1, elem_size: 24, max: 16, split_first: 16 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want split_first max smaller than elem_size error")
	}
}

func TestLoadCapturePolicyRequiresElementSizeForRetCount(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [epoll_wait]
    exit:
      payloads:
        - { arg: 1, kind: struct, direction: out, count_from_ret: true, max: 512 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want missing elem_size error")
	}
}

func TestLoadCapturePolicyRequiresUserArgForClampOffset(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [accept]
    exit:
      payloads:
        - { arg: 1, kind: struct, direction: out, clamp_u32_from_offset: 768, max: 128 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want clamp without len_from_user_arg error")
	}
}

func TestLoadCapturePolicyRejectsInvalidArgBitsLength(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [ioctl]
    enter:
      payloads:
        - { arg: 2, kind: raw, direction: in, len_from_arg_bits: { arg: 1, shift: 16, mask: 0 }, max: 512 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want invalid len_from_arg_bits error")
	}
}

func TestLoadCapturePolicyRejectsInvalidArgCasesLength(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [fcntl]
    enter:
      payloads:
        - { arg: 2, kind: raw, direction: in, len_from_arg_cases: { arg: 1, cases: [{ size: 0, values: [15] }] }, max: 32 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want invalid len_from_arg_cases error")
	}
}

func TestLoadCapturePolicyRejectsInvalidStringBytesSwitch(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [fsconfig]
    enter:
      payloads:
        - { arg: 3, kind: string_or_bytes, direction: in, string_bytes_switch: { selector_arg: -1, bytes_value: 2, len_from_arg: 4 }, max: 4096 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want invalid string_bytes_switch error")
	}
}

func TestLoadCapturePolicyRejectsMinGreaterThanMax(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	path := filepath.Join(t.TempDir(), "capture_rules.yaml")
	data := []byte(`rules:
  - syscalls: [openat2]
    enter:
      payloads:
        - { arg: 2, kind: struct, direction: in, len_from_arg: 3, min: 128, max: 64 }
`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write test policy: %v", err)
	}

	if err := loadCapturePolicy(path); err == nil {
		t.Fatalf("loadCapturePolicy() error = nil, want invalid min/max error")
	}
}

func TestProductCapturePolicyHasUniqueSyscalls(t *testing.T) {
	oldConfig := globalConfig
	defer func() { globalConfig = oldConfig }()

	if err := loadCapturePolicy("capture_rules.yaml"); err != nil {
		t.Fatalf("loadCapturePolicy(product) error = %v", err)
	}
	seen := make(map[string]int)
	for ruleIndex, rule := range globalConfig.Rules {
		for _, sc := range rule.Syscalls {
			if firstRule, ok := seen[sc]; ok {
				t.Fatalf("syscall %s appears in capture rules %d and %d", sc, firstRule, ruleIndex)
			}
			seen[sc] = ruleIndex
		}
	}
}
