package handler

import "testing"

func TestSnapshotReaderExposesOnlyPayloadSections(t *testing.T) {
	ctx := &Context{
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindStruct,
				Direction: PayloadDirectionOut,
				ArgIndex:  2,
				UserPtr:   0x1000,
				UserLen:   4,
				CopiedLen: 4,
				ProbeRet:  0,
				Data:      []byte{1, 2, 3, 4},
			},
		},
	}

	var reader SnapshotReader = ctx
	section, ok := reader.Section(2, PayloadKindStruct)
	if !ok {
		t.Fatal("SnapshotReader did not expose payload section")
	}
	if section.UserPtr != 0x1000 || section.CopiedLen != 4 {
		t.Fatalf("section metadata = ptr %#x copied %d, want ptr 0x1000 copied 4", section.UserPtr, section.CopiedLen)
	}
	if string(section.Data) != string([]byte{1, 2, 3, 4}) {
		t.Fatalf("section data = %v", section.Data)
	}
}

func TestSnapshotReaderDoesNotMatchLegacyFixedBuffer(t *testing.T) {
	ctx := &Context{
		PayloadSections: []PayloadSection{
			{
				Kind:      PayloadKindBytes,
				Direction: PayloadDirectionIn,
				ArgIndex:  1,
				ProbeRet:  0,
				Data:      []byte{7, 7},
			},
		},
	}

	var reader SnapshotReader = ctx
	if _, ok := reader.Section(1, PayloadKindStruct); ok {
		t.Fatal("SnapshotReader matched fixed buffer data without a struct payload section")
	}
}
