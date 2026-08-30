package handler

import (
	"encoding/binary"
	"strings"
	"testing"

	"strace-go/pkg/event"
	"strace-go/pkg/meta"
)

func makeTimexStruct(modes uint32) []byte {
	data := make([]byte, 208)
	binary.LittleEndian.PutUint32(data[0:4], modes)
	return data
}

func makeTimeTValue(sec int64) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint64(data, uint64(sec))
	return data
}

func TestTimeHandlerFormatsTimeSyscall(t *testing.T) {
	tests := []struct {
		name       string
		arg        uint64
		ret        int64
		payload    []PayloadSection
		wantArg    string
		wantReturn string
	}{
		{
			name: "output snapshot",
			arg:  0x1000,
			ret:  1492350678,
			payload: []PayloadSection{
				{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 0, ProbeRet: 0, Data: makeTimeTValue(1492350678)},
			},
			wantArg:    "[1492350678 /* 2017-04-16T13:51:18+0000 */]",
			wantReturn: "2017-04-16T13:51:18+0000",
		},
		{
			name:       "null output",
			ret:        1492350678,
			wantArg:    "NULL",
			wantReturn: "2017-04-16T13:51:18+0000",
		},
		{
			name:    "failed output",
			arg:     0x1000,
			ret:     -14,
			wantArg: "0x1000",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := &Context{
				SysName:         "time",
				Args:            [6]uint64{test.arg},
				Ret:             test.ret,
				PayloadSections: test.payload,
			}

			got := (&TimeHandler{}).Handle(ctx)
			if len(got.ArgParts) != 1 || got.ArgParts[0] != test.wantArg {
				t.Fatalf("time args = %v, want [%q]", got.ArgParts, test.wantArg)
			}
			if got.ReturnDesc != test.wantReturn {
				t.Fatalf("time return description = %q, want %q", got.ReturnDesc, test.wantReturn)
			}
		})
	}
}

func TestTimeHandlerClockGettimeDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(9, 10)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "clock_gettime",
		Args:         [6]uint64{0, 0x1000},
		Ret:          0,
		ProbeRetExit: -1,
		Decoder:      decoder,
		Meta:         meta.NewCatalog("abbrev"),
	}

	got := (&TimeHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 {
		t.Fatalf("ArgParts len = %d, want 2", len(got.ArgParts))
	}
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("clock_gettime timespec = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerClockSettimeIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(99, 100)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:           1234,
		Tid:           1234,
		SysName:       "clock_settime",
		Args:          [6]uint64{0, 0x1000},
		Ret:           0,
		ProbeRetEnter: 0,
		ProbeRetExit:  -1,
		Decoder:       decoder,
		Meta:          meta.NewCatalog("abbrev"),
	}

	got := (&TimeHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 {
		t.Fatalf("ArgParts len = %d, want 2", len(got.ArgParts))
	}
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("clock_settime timespec = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerClockGettimeUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(99, 100)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "clock_gettime",
		Args:    [6]uint64{0, 0x1000},
		Ret:     0,
		Decoder: event.NewDecoder(),
		Meta:    meta.NewCatalog("abbrev"),
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeTimeStruct(5, 6)},
		},
	}

	got := (&TimeHandler{}).Handle(ctx)
	if got.ArgParts[1] != "{tv_sec=5, tv_nsec=6}" {
		t.Fatalf("clock_gettime timespec = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerClockSettimeUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimeStruct(99, 100)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "clock_settime",
		Args:    [6]uint64{0, 0x1000},
		Ret:     0,
		Decoder: event.NewDecoder(),
		Meta:    meta.NewCatalog("abbrev"),
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 1, ProbeRet: 0, Data: makeTimeStruct(7, 8)},
		},
	}

	got := (&TimeHandler{}).Handle(ctx)
	if got.ArgParts[1] != "{tv_sec=7, tv_nsec=8}" {
		t.Fatalf("clock_settime timespec = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerAdjtimexDoesNotReadWhenFallbackDisabled(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimexStruct(7)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "adjtimex",
		Args:         [6]uint64{0x1000},
		Ret:          -1,
		ProbeRetExit: -1,
		Decoder:      decoder,
		Meta:         meta.NewCatalog("abbrev"),
	}

	got := (&TimeHandler{}).Handle(ctx)
	if len(got.ArgParts) != 1 {
		t.Fatalf("ArgParts len = %d, want 1", len(got.ArgParts))
	}
	if got.ArgParts[0] != "0x1000" {
		t.Fatalf("adjtimex timex = %q, want pointer fallback", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerAdjtimexIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimexStruct(7)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "adjtimex",
		Args:         [6]uint64{0x1000},
		Ret:          0,
		ProbeRetExit: 0,
		Decoder:      decoder,
		Meta:         meta.NewCatalog("abbrev"),
	}

	got := (&TimeHandler{}).Handle(ctx)
	if len(got.ArgParts) != 1 {
		t.Fatalf("ArgParts len = %d, want 1", len(got.ArgParts))
	}
	if got.ArgParts[0] != "0x1000" {
		t.Fatalf("adjtimex timex = %q, want pointer fallback", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerAdjtimexUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimexStruct(7)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "adjtimex",
		Args:    [6]uint64{0x1000},
		Ret:     0,
		Decoder: event.NewDecoder(),
		Meta:    meta.NewCatalog("abbrev"),
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 0, ProbeRet: 0, Data: makeTimexStruct(7)},
		},
	}

	got := (&TimeHandler{}).Handle(ctx)
	if !strings.HasPrefix(got.ArgParts[0], "{modes=7,") {
		t.Fatalf("adjtimex timex = %q", got.ArgParts[0])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerClockAdjtimeIgnoresProbeSuccessWithoutPayloadSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimexStruct(9)}
	decoder := event.NewDecoder()
	ctx := &Context{
		Pid:          1234,
		Tid:          1234,
		SysName:      "clock_adjtime",
		Args:         [6]uint64{0, 0x1000},
		Ret:          0,
		ProbeRetExit: 0,
		Decoder:      decoder,
		Meta:         meta.NewCatalog("abbrev"),
	}

	got := (&TimeHandler{}).Handle(ctx)
	if len(got.ArgParts) != 2 {
		t.Fatalf("ArgParts len = %d, want 2", len(got.ArgParts))
	}
	if got.ArgParts[1] != "0x1000" {
		t.Fatalf("clock_adjtime timex = %q, want pointer fallback", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}

func TestTimeHandlerClockAdjtimeUsesPayloadStructSection(t *testing.T) {
	reader := &fetchPolicyMemoryReader{data: makeTimexStruct(9)}
	ctx := &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: "clock_adjtime",
		Args:    [6]uint64{0, 0x1000},
		Ret:     0,
		Decoder: event.NewDecoder(),
		Meta:    meta.NewCatalog("abbrev"),
		PayloadSections: []PayloadSection{
			{Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 1, ProbeRet: 0, Data: makeTimexStruct(9)},
		},
	}

	got := (&TimeHandler{}).Handle(ctx)
	if !strings.HasPrefix(got.ArgParts[1], "{modes=9,") {
		t.Fatalf("clock_adjtime timex = %q", got.ArgParts[1])
	}
	if reader.reads != 0 {
		t.Fatalf("memory reads = %d, want 0", reader.reads)
	}
}
