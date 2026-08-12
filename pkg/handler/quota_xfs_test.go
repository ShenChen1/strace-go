package handler

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

const (
	testQuotaXOn         = uint64(0x5801)
	testQuotaXOff        = uint64(0x5802)
	testQuotaXGetQuota   = uint64(0x5803)
	testQuotaXSetQLim    = uint64(0x5804)
	testQuotaXGetQStat   = uint64(0x5805)
	testQuotaXQuotaRm    = uint64(0x5806)
	testQuotaXQuotaSync  = uint64(0x5807)
	testQuotaXGetQStatV  = uint64(0x5808)
	testQuotaXGetNext    = uint64(0x5809)
	testQuotaXFlags      = uint32(0x3f)
	testQuotaXDqblkFlags = uint32(0x7)
)

func testQuotaStruct(argIndex int, ptr uint64, direction PayloadDirection, data []byte) PayloadSection {
	return PayloadSection{
		Kind: PayloadKindStruct, Direction: direction, ArgIndex: argIndex,
		UserPtr: ptr, UserLen: uint32(len(data)), CopiedLen: uint32(len(data)), Data: data,
	}
}

func testQuotaUint32(value uint32) []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, value)
	return data
}

func testXFSDiskQuota() []byte {
	data := make([]byte, 112)
	data[0] = 1
	data[1] = 7
	binary.LittleEndian.PutUint16(data[2:4], 0x9190)
	binary.LittleEndian.PutUint32(data[4:8], 3141592653)
	for index, value := range []uint64{10, 20, 30, 40, 50, 60} {
		binary.LittleEndian.PutUint64(data[8+index*8:16+index*8], value)
	}
	binary.LittleEndian.PutUint32(data[56:60], 0xfffffff9)
	binary.LittleEndian.PutUint32(data[60:64], 8)
	binary.LittleEndian.PutUint16(data[64:66], 9)
	binary.LittleEndian.PutUint16(data[66:68], 10)
	for index, value := range []uint64{70, 80, 90} {
		binary.LittleEndian.PutUint64(data[72+index*8:80+index*8], value)
	}
	binary.LittleEndian.PutUint32(data[96:100], 11)
	binary.LittleEndian.PutUint16(data[100:102], 12)
	return data
}

func testXFSQuotaStat() []byte {
	data := make([]byte, 80)
	data[0] = 1
	binary.LittleEndian.PutUint16(data[2:4], uint16(testQuotaXFlags))
	for offset, value := range map[int]uint64{8: 10, 16: 20, 32: 30, 40: 40} {
		binary.LittleEndian.PutUint64(data[offset:offset+8], value)
	}
	binary.LittleEndian.PutUint32(data[24:28], 2)
	binary.LittleEndian.PutUint32(data[48:52], 4)
	binary.LittleEndian.PutUint32(data[56:60], 5)
	binary.LittleEndian.PutUint32(data[60:64], 6)
	binary.LittleEndian.PutUint32(data[64:68], 7)
	binary.LittleEndian.PutUint32(data[68:72], 8)
	binary.LittleEndian.PutUint16(data[72:74], 9)
	binary.LittleEndian.PutUint16(data[74:76], 10)
	return data
}

func testXFSQuotaStatV() []byte {
	data := make([]byte, 160)
	data[0] = 1
	binary.LittleEndian.PutUint16(data[2:4], uint16(testQuotaXFlags))
	binary.LittleEndian.PutUint32(data[4:8], 5)
	for offset, value := range map[int]uint64{8: 10, 16: 20, 32: 30, 40: 40, 56: 50, 64: 60} {
		binary.LittleEndian.PutUint64(data[offset:offset+8], value)
	}
	binary.LittleEndian.PutUint32(data[24:28], 2)
	binary.LittleEndian.PutUint32(data[48:52], 4)
	binary.LittleEndian.PutUint32(data[72:76], 6)
	binary.LittleEndian.PutUint32(data[80:84], 7)
	binary.LittleEndian.PutUint32(data[84:88], 8)
	binary.LittleEndian.PutUint32(data[88:92], 9)
	binary.LittleEndian.PutUint16(data[92:94], 10)
	binary.LittleEndian.PutUint16(data[94:96], 11)
	return data
}

func TestQuotaXFSFlagCommandsSkipIDAndUseEnterSnapshot(t *testing.T) {
	for _, tc := range []struct {
		command uint64
		table   string
		want    string
	}{
		{testQuotaXOn, "xfs_quota_flags", "[FS_QUOTA_UDQ_ACCT|FS_QUOTA_UDQ_ENFD|FS_QUOTA_GDQ_ACCT|FS_QUOTA_GDQ_ENFD|FS_QUOTA_PDQ_ACCT|FS_QUOTA_PDQ_ENFD]"},
		{testQuotaXOff, "xfs_quota_flags", "[FS_QUOTA_UDQ_ACCT|FS_QUOTA_UDQ_ENFD|FS_QUOTA_GDQ_ACCT|FS_QUOTA_GDQ_ENFD|FS_QUOTA_PDQ_ACCT|FS_QUOTA_PDQ_ENFD]"},
		{testQuotaXQuotaRm, "xfs_dqblk_flags", "[FS_USER_QUOTA|FS_PROJ_QUOTA|FS_GROUP_QUOTA]"},
	} {
		args := [6]uint64{testQuotaCommand(tc.command, testQuotaUser), 0x1000, ^uint64(0), 0x2000}
		ctx := testQuotaContext("quotactl", args, -1)
		value := testQuotaXFlags
		if tc.table == "xfs_dqblk_flags" {
			value = testQuotaXDqblkFlags
		}
		ctx.PayloadSections = []PayloadSection{testQuotaStruct(3, args[3], PayloadDirectionIn, testQuotaUint32(value))}
		got := NewRegistry().Resolve("quotactl").Handle(ctx).ArgParts
		if len(got) != 3 || got[2] != tc.want {
			t.Errorf("command %#x args = %#v, want final %q without id", tc.command, got, tc.want)
		}
	}
}

func TestQuotaXFSSetQLimUsesEnterDiskQuota(t *testing.T) {
	args := [6]uint64{testQuotaCommand(testQuotaXSetQLim, testQuotaProject), 0x1000, 3141592653, 0x3000}
	ctx := testQuotaContext("quotactl", args, -1)
	ctx.PayloadSections = []PayloadSection{testQuotaStruct(3, args[3], PayloadDirectionIn, testXFSDiskQuota())}
	got := NewRegistry().Resolve("quotactl").Handle(ctx).ArgParts
	if len(got) != 4 || !strings.Contains(got[3], "d_flags=FS_USER_QUOTA|FS_PROJ_QUOTA|FS_GROUP_QUOTA") ||
		!strings.Contains(got[3], "d_icount=60, ...") {
		t.Fatalf("Q_XSETQLIM args = %#v, want abbreviated enter disk quota", got)
	}
}

func TestQuotaXFSGetQuotaRequiresSuccessfulExit(t *testing.T) {
	args := [6]uint64{testQuotaCommand(testQuotaXGetQuota, testQuotaUser), 0x1000, 1000, 0x4000}
	ctx := testQuotaContext("quotactl", args, -1)
	ctx.PayloadSections = []PayloadSection{testQuotaStruct(3, args[3], PayloadDirectionOut, testXFSDiskQuota())}
	got := NewRegistry().Resolve("quotactl").Handle(ctx).ArgParts
	if len(got) != 4 || got[3] != "0x4000" {
		t.Fatalf("failed Q_XGETQUOTA args = %#v, want pointer fallback", got)
	}
	ctx.Ret = 0
	got = NewRegistry().Resolve("quotactl").Handle(ctx).ArgParts
	if !strings.Contains(got[3], "d_blk_hardlimit=10") {
		t.Fatalf("successful Q_XGETQUOTA args = %#v, want exit disk quota", got)
	}
}

func TestQuotaXFSGetStatsUseExitStructures(t *testing.T) {
	ctx := testQuotaContext("quotactl", [6]uint64{testQuotaCommand(testQuotaXGetQStat, testQuotaUser), 0, 0, 0x5000}, 0)
	cliOptionsForTest(ctx).Verbose = true
	ctx.PayloadSections = []PayloadSection{testQuotaStruct(3, ctx.Args[3], PayloadDirectionOut, testXFSQuotaStat())}
	got := NewRegistry().Resolve("quotactl").Handle(ctx).ArgParts
	if len(got) != 3 || !strings.Contains(got[2], "qs_uquota={qfs_ino=10, qfs_nblks=20, qfs_nextents=2}") {
		t.Fatalf("Q_XGETQSTAT args = %#v, want verbose stat", got)
	}

	ctx.Args[0] = testQuotaCommand(testQuotaXGetQStatV, testQuotaProject)
	ctx.PayloadSections = []PayloadSection{testQuotaStruct(3, ctx.Args[3], PayloadDirectionOut, testXFSQuotaStatV())}
	got = NewRegistry().Resolve("quotactl").Handle(ctx).ArgParts
	if len(got) != 3 || !strings.Contains(got[2], "qs_pquota={qfs_ino=50, qfs_nblks=60, qfs_nextents=6}") {
		t.Fatalf("Q_XGETQSTATV args = %#v, want verbose statv", got)
	}
}

func TestQuotaXFSQuotaSyncSkipsIDAndAddr(t *testing.T) {
	args := [6]uint64{testQuotaCommand(testQuotaXQuotaSync, 0xff), 0, ^uint64(0), 0x6000}
	ctx := testQuotaContext("quotactl", args, -1)
	want := []string{"QCMD(Q_XQUOTASYNC, 0xff /* ???QUOTA */)", "NULL"}
	if got := NewRegistry().Resolve("quotactl").Handle(ctx).ArgParts; !reflect.DeepEqual(got, want) {
		t.Fatalf("Q_XQUOTASYNC args = %#v, want %#v", got, want)
	}
}

func TestQuotaXFSGetNextUsesIDAndDiskQuota(t *testing.T) {
	args := [6]uint64{testQuotaCommand(testQuotaXGetNext, testQuotaUser), 0, 123, 0x7000}
	ctx := testQuotaContext("quotactl", args, 0)
	ctx.PayloadSections = []PayloadSection{testQuotaStruct(3, args[3], PayloadDirectionOut, testXFSDiskQuota())}
	got := NewRegistry().Resolve("quotactl").Handle(ctx).ArgParts
	if len(got) != 4 || got[2] != "123" || !strings.Contains(got[3], "d_id=3141592653") {
		t.Fatalf("Q_XGETNEXTQUOTA args = %#v, want id and disk quota", got)
	}
}

func TestQuotaXFSFdVariantUsesSameCommandLayout(t *testing.T) {
	args := [6]uint64{9, testQuotaCommand(testQuotaXOn, testQuotaUser), ^uint64(0), 0x8000}
	ctx := testQuotaContext("quotactl_fd", args, -1)
	ctx.PayloadSections = []PayloadSection{
		testQuotaStruct(3, args[3], PayloadDirectionIn, testQuotaUint32(testQuotaXFlags)),
	}
	want := []string{
		"9",
		"QCMD(Q_XQUOTAON, USRQUOTA)",
		"[FS_QUOTA_UDQ_ACCT|FS_QUOTA_UDQ_ENFD|FS_QUOTA_GDQ_ACCT|FS_QUOTA_GDQ_ENFD|FS_QUOTA_PDQ_ACCT|FS_QUOTA_PDQ_ENFD]",
	}
	if got := NewRegistry().Resolve("quotactl_fd").Handle(ctx).ArgParts; !reflect.DeepEqual(got, want) {
		t.Fatalf("quotactl_fd Q_XQUOTAON args = %#v, want %#v", got, want)
	}
}

func TestQuotaXFSTruncatedSnapshotFallsBackToPointer(t *testing.T) {
	args := [6]uint64{testQuotaCommand(testQuotaXSetQLim, testQuotaUser), 0, 123, 0x9000}
	ctx := testQuotaContext("quotactl", args, -1)
	ctx.PayloadSections = []PayloadSection{
		testQuotaStruct(3, args[3], PayloadDirectionIn, make([]byte, quotaXFSDiskSize-1)),
	}
	got := NewRegistry().Resolve("quotactl").Handle(ctx).ArgParts
	if len(got) != 4 || got[3] != "0x9000" {
		t.Fatalf("truncated Q_XSETQLIM args = %#v, want pointer fallback", got)
	}
}
