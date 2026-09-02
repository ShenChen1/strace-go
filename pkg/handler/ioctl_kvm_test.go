package handler

import (
	"reflect"
	"testing"

	"strace-go/pkg/event"
)

func TestIoctlKVMRunUsesUpstreamArgumentSpelling(t *testing.T) {
	ctx := newIoctlPolicyContext(&ioctlPolicyMemoryReader{}, event.NewDecoder())
	ctx.Args = [6]uint64{3, kvmRunIOCTL, 0}

	result := (&IoctlHandler{}).Handle(ctx)
	want := []string{"3", "KVM_RUN", "0"}
	if !reflect.DeepEqual(result.ArgParts, want) {
		t.Fatalf("KVM_RUN arguments = %#v, want %#v", result.ArgParts, want)
	}
}
