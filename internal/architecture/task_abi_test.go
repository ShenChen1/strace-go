package architecture

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNativeTaskABIGuards(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	header := filepath.Join(filepath.Dir(file), "../../bpf/native_task_abi.h")
	for _, target := range []string{"x86", "arm64"} {
		t.Run(target, func(t *testing.T) {
			source := fmt.Sprintf(taskABITestSource, header)
			dir := t.TempDir()
			path := filepath.Join(dir, "guard.c")
			if err := os.WriteFile(path, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(dir, "guard")
			cmd := exec.Command("clang", "-Wno-unknown-attributes", "-D__TARGET_ARCH_"+target, path, "-o", binary)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("compile guard: %v\n%s", err, out)
			}
			if out, err := exec.Command(binary).CombinedOutput(); err != nil {
				t.Fatalf("ABI guard contract: %v\n%s", err, out)
			}
		})
	}
}

const taskABITestSource = `
#include <stdint.h>
#include <assert.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t s64;
struct task_struct { struct { u32 status; unsigned long flags; } thread_info; } task;
struct pt_regs { u64 ax; };
static int read_failed;
static void *bpf_get_current_task(void) { return &task; }
#define BPF_CORE_READ_INTO(out, src, field) (read_failed ? -1 : (*(out) = (src)->field, 0))
#define BPF_CORE_READ(src, field) ((src)->field)
#include %q
int main(void) {
    assert(current_syscall_has_native_abi(0));
    assert(current_syscall_has_native_abi(173));
#if defined(__TARGET_ARCH_x86)
    assert(!current_syscall_has_native_abi(0x40000000U));
    task.thread_info.status = 2;
#else
    task.thread_info.flags = 1UL << 22;
#endif
    assert(!current_syscall_has_native_abi(20));
    task.thread_info.status = 0;
    task.thread_info.flags = 0;
    read_failed = 1;
    assert(!current_syscall_has_native_abi(63));
    return 0;
}
`
