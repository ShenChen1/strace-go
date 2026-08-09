package handler

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	"strace-go/pkg/cli"
	"strace-go/pkg/event"
)

const (
	testQuotaUser       = uint64(0)
	testQuotaProject    = uint64(2)
	testQuotaFormatVFS1 = uint64(4)
	testQuotaOn         = uint64(0x800002)
	testQuotaGetFmt     = uint64(0x800004)
	testQuotaGetQuota   = uint64(0x800007)
	testQuotaSetQuota   = uint64(0x800008)
)

func testQuotaCommand(command uint64, quotaType uint64) uint64 {
	return command<<8 | quotaType
}

func testQuotaContext(name string, args [6]uint64, ret int64) *Context {
	return &Context{
		Pid:     1234,
		Tid:     1234,
		SysName: name,
		Args:    args,
		Ret:     ret,
		Decoder: event.NewDecoder(),
		Opts:    &cli.Options{XlatFormat: "abbrev", StringLimit: 32},
	}
}

func testQuotaString(argIndex int, ptr uint64, value string) PayloadSection {
	data := append([]byte(value), 0)
	return PayloadSection{
		Kind:      PayloadKindString,
		Direction: PayloadDirectionIn,
		ArgIndex:  argIndex,
		UserPtr:   ptr,
		UserLen:   uint32(len(data)),
		CopiedLen: uint32(len(data)),
		Data:      data,
	}
}

func testQuotaDqblk() []byte {
	data := make([]byte, 72)
	for index, value := range []uint64{1, 2, 3, 4, 5, 6, 7, 8} {
		binary.LittleEndian.PutUint64(data[index*8:index*8+8], value)
	}
	binary.LittleEndian.PutUint32(data[64:68], 1)
	return data
}

func TestQuotaSyscallsUseSpecializedHandler(t *testing.T) {
	for _, name := range []string{"quotactl", "quotactl_fd"} {
		if reflect.TypeOf(Get(name)) == reflect.TypeOf(GetDefault()) {
			t.Errorf("%s uses default handler", name)
		}
	}
}

func TestQuotaOnUsesEnterPathSnapshots(t *testing.T) {
	args := [6]uint64{
		testQuotaCommand(testQuotaOn, testQuotaUser),
		0x1000,
		testQuotaFormatVFS1,
		0x2000,
	}
	ctx := testQuotaContext("quotactl", args, -1)
	ctx.PayloadSections = []PayloadSection{
		testQuotaString(1, args[1], "/dev/sda1"),
		testQuotaString(3, args[3], "/quota.user"),
	}

	got := Get("quotactl").Handle(ctx).ArgParts
	want := []string{
		"QCMD(Q_QUOTAON, USRQUOTA)",
		`"/dev/sda1"`,
		"QFMT_VFS_V1",
		`"/quota.user"`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("quotactl Q_QUOTAON args = %#v, want %#v", got, want)
	}
}

func TestQuotaSetUsesEnterStructAfterFailure(t *testing.T) {
	args := [6]uint64{
		testQuotaCommand(testQuotaSetQuota, testQuotaProject),
		0x1000,
		3141592653,
		0x3000,
	}
	ctx := testQuotaContext("quotactl", args, -1)
	ctx.PayloadSections = []PayloadSection{
		testQuotaString(1, args[1], "/dev/bogus/"),
		{
			Kind: PayloadKindStruct, Direction: PayloadDirectionIn, ArgIndex: 3,
			UserPtr: args[3], UserLen: 72, CopiedLen: 72, Data: testQuotaDqblk(),
		},
	}

	got := Get("quotactl").Handle(ctx).ArgParts
	if len(got) != 4 || !strings.Contains(got[3], "dqb_curinodes=6") {
		t.Fatalf("quotactl Q_SETQUOTA args = %#v, want enter dqblk snapshot", got)
	}
	if strings.Contains(got[3], "0x3000") {
		t.Fatalf("quotactl Q_SETQUOTA addr = %q, unexpectedly used pointer fallback", got[3])
	}
}

func TestQuotaGetRequiresSuccessfulExitSnapshot(t *testing.T) {
	args := [6]uint64{
		testQuotaCommand(testQuotaGetQuota, testQuotaUser),
		0x1000,
		1000,
		0x4000,
	}
	ctx := testQuotaContext("quotactl", args, -1)
	ctx.PayloadSections = []PayloadSection{
		testQuotaString(1, args[1], "/dev/sda1"),
		{
			Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 3,
			UserPtr: args[3], UserLen: 72, CopiedLen: 72, Data: testQuotaDqblk(),
		},
	}
	got := Get("quotactl").Handle(ctx).ArgParts
	if len(got) != 4 || got[3] != "0x4000" {
		t.Fatalf("failed Q_GETQUOTA args = %#v, want OUT pointer fallback", got)
	}

	ctx.Ret = 0
	got = Get("quotactl").Handle(ctx).ArgParts
	if len(got) != 4 || !strings.Contains(got[3], "dqb_bhardlimit=1") {
		t.Fatalf("successful Q_GETQUOTA args = %#v, want exit dqblk snapshot", got)
	}
}

func TestQuotaIDPreservesUnsignedValuesExceptMinusOne(t *testing.T) {
	if got := formatQuotaID(3141592653); got != "3141592653" {
		t.Fatalf("formatQuotaID(3141592653) = %q", got)
	}
	if got := formatQuotaID(^uint64(0)); got != "-1" {
		t.Fatalf("formatQuotaID(-1) = %q", got)
	}
}

func TestQuotaCommandVerboseWrapsSymbolicQcmd(t *testing.T) {
	ctx := testQuotaContext("quotactl", [6]uint64{}, 0)
	ctx.Opts.XlatFormat = "verbose"
	qcmd := uint32(testQuotaCommand(testQuotaOn, testQuotaUser))
	want := "2147484160 /* QCMD(Q_QUOTAON, USRQUOTA) */"
	if got := formatQuotaCommand(ctx, qcmd); got != want {
		t.Fatalf("formatQuotaCommand(verbose) = %q, want %q", got, want)
	}
}

func TestQuotaFlagsOnlyAnnotateFullyUnknownValues(t *testing.T) {
	const unknown = uint32(0x20)
	if got := quotaFlagNames(1|unknown, "if_dqinfo_flags", "DQF_???"); got != "DQF_ROOT_SQUASH|0x20" {
		t.Fatalf("mixed quota flags = %q", got)
	}
	if got := quotaFlagNames(unknown, "if_dqinfo_flags", "DQF_???"); got != "0x20 /* DQF_??? */" {
		t.Fatalf("unknown quota flags = %q", got)
	}
}

func TestQuotaFdGetFmtUsesExitSnapshot(t *testing.T) {
	args := [6]uint64{9, testQuotaCommand(testQuotaGetFmt, testQuotaUser), 0, 0x5000}
	ctx := testQuotaContext("quotactl_fd", args, 0)
	formatData := make([]byte, 4)
	binary.LittleEndian.PutUint32(formatData, uint32(testQuotaFormatVFS1))
	ctx.PayloadSections = []PayloadSection{{
		Kind: PayloadKindStruct, Direction: PayloadDirectionOut, ArgIndex: 3,
		UserPtr: args[3], UserLen: 4, CopiedLen: 4, Data: formatData,
	}}

	got := Get("quotactl_fd").Handle(ctx).ArgParts
	want := []string{"9", "QCMD(Q_GETFMT, USRQUOTA)", "[QFMT_VFS_V1]"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("quotactl_fd Q_GETFMT args = %#v, want %#v", got, want)
	}
}
