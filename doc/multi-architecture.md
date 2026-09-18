# amd64 / arm64 架构审计与实施记录

## Problem 1-Pager

- Context：纯 eBPF tracer 使用按名称声明的 capture manifest、按 ID 索引的路由和元数据、CO-RE 内核读取、有界 userspace ABI 快照。
- Problem：提交的 syscall table/BPF bytecode 来自 amd64，却被所有 little-endian Go target 使用；跨编译成功会掩盖错误语义。
- Goal：linux/amd64、linux/arm64 的 native 64-bit syscall ABI，构建目标、号码、语义、BPF、解码与验证形成可检查的合同。
- Non-Goals：32-bit、i386、arm32、x32、任意 ABI 插件、ptrace/procfs 内存补读、所有 Linux 架构。
- Constraints：保持 amd64 输出，小提交；先读源码与调用路径再修改；失败优先于错误解码；构建证据和原生语义证据分别记录。

## Phase 1：架构审计（修改实现前）

审计基线：2026-09-13，工作树原有 `.antigravitycli/` 未跟踪目录，不属于此次修改。
扫描第一方仓库、生成文件、生成器、测试、文档和构建入口；上游 submodule 作为 ABI/语义参考，不整体改写。
执行了用户指定的架构名称、syscall 号码、寄存器、布局、生成入口检索。
下面按同一依赖的 owner 分组，不将每个使用相同宏的 capture helper 重复列为一个设计问题。

分类：N = architecture-neutral；A = architecture-dependent but already abstracted；H = hard-coded architecture dependency；U = unknown / needs validation。

### 1. build-time x86_64 assumptions

| 分类 | 位置 | 发现与影响 |
| --- | --- | --- |
| H | `cmd/strace-go/main.go` | 九条 bpf2go 指令硬编码 `/usr/include/x86_64-linux-gnu`，没有统一 target。 |
| H | `cmd/strace-go/event_integrity_benchmark_test.go` | 测试编译器也重复该路径。 |
| H | `build.sh` | 清理全局生成物、sudo go generate、最后 host go build；没有明确 target 或交叉模式。 |
| A | `go.mod` | 已固定 x/sys、cilium/ebpf 版本，可复用其源码和目标选择能力。 |
| N | BPF C include closure | `clang -M` 确认 core 仅依赖项目头、vmlinux.h 和 libbpf helper 头；没有 libc multiarch 间接依赖。 |
| U | 双架构交叉生成 | 尚未验证全部 collection 的目标生成；需分别编译并检查 Go tags、BTF relocation 和语义常量。 |

实测 core 和 recvmsg 在没有额外 `-I` 的条件下编译通过。不能从这两个对象推断全部目标已通过。
`bpfel` 仅表示 BPF little-endian，两种 CPU 均使用它。Linux 内核源码目录名 arm64、工具链 triplet aarch64 与 Go arm64 也须区分。

### 2. runtime x86_64 assumptions

| 分类 | 位置 | 发现与影响 |
| --- | --- | --- |
| H | `main.go:runMain/runTraceSession` | 启动未检查支持架构、metadata 和 BPF object 一致性。 |
| N | `bpf/strace.c`、`bpf_attach.go` | syscall 使用普通 `tracepoint/raw_syscalls/sys_enter/sys_exit`，读取记录中的 id、args[6]、ret；不是 BPF RAW_TRACEPOINT ctx 的参数格式。 |
| H | `bpf/recvmsg_kretprobe_dispatch.h` | 三次 `BPF_CORE_READ(ctx, ax)` 读取 x86 返回寄存器；ARM64 无此字段。 |
| H | `bpf_attach.go:attachRecvmsgKretprobe` | fallback symbol 是 `__x64_sys_recvmsg`；需要目标 wrapper 名称。 |
| H | `strace.c`、`runtime_abi_writer.go` | 无 ABI 检测，固定 compat rt_sigreturn=173；会跳过 native amd64 ioperm、arm64 getppid。 |
| A | `syscall_lifecycle_ids.go` | exit/exit_group 按 metadata 名称解析，数据正确即可复用。 |
| A | `lifecycle_state.h` | clone flags 在 args[0]、clone3 flags 在结构首字段，两个 native ABI 可共用。 |
| H | `syscall_event_traits.go` | ID 0 特例关联 read；ARM64 的 ID 0 是 io_setup。 |
| U | `kvm_dispatch.h` | 固定 kvm_userspace_exit tracepoint 记录；需验证 ARM64 tracepoint 是否存在及字段合同，否则明确禁用对应增强能力。 |
| U | compat 检测 | 目前无检查。Linux 有 x86 TS_COMPAT、x32 syscall bit、ARM64 TIF_32BIT；必须验证入口与退出时机，不能仅检查 ELF 或 kernel machine。 |

Linux trace event 源码在形成普通 tracepoint 记录时调用 syscall_get_arguments，处理寄存器约定；native LP64 的 id/args/ret 均为 8 字节。
这只证明主 observation path 不需要寄存器抽象，不能推广到 recvmsg kretprobe。

### 3. syscall-number assumptions

| 分类 | 位置 | 发现与影响 |
| --- | --- | --- |
| A/H | `generate-syscalls/unix_syscall_source.go` | 已解析固定版本 x/sys Go constants，无需抄 Linux 号码表；但文件选择隐式使用 runtime.GOARCH/GOOS。 |
| H | `pkg/meta/syscall_table.go` | 单套 map，read=0、openat=257 等 amd64 号码，全目标共享。 |
| H | `bpf/syscall_numbers_generated.h` | 单套 SYS_*；大多数为编译时宏，loader 重写少数 volatile const 无法修复整个 object。 |
| A | `generate-syscalls/loader.go` | 号码与语义按名称 merge，已有重复 ID、缺失 semantic 错误检查。 |
| U | `semantic_catalog_generated.go` | 仅名称和 arity/flags；需处理 ARM64 syscall availability 与非 syscall 哨兵常量。 |
| A | `bpf_routes.go`、capture manifest | 路由按名称声明，再按传入 table 生成 ID map；已有重复名称、容量、slot 校验，缺少双架构合同测试。 |
| A | syscall filter、FD 分类、专项注册 | 主要使用名称或 SYS_*，数据源修复后复用；不能把 ARM64 不存在的 syscall 注册成另一号码。 |
| H | CLI personality selector | 接受 32/x32 qualification 不等于存在相应 decoder；需明确 native-only 语义。 |

固定 x/sys v0.47.0 检查：amd64 有 385 个 SYS_*，arm64 有 328 个，其中 ARCH_SPECIFIC_SYSCALL 是范围标记，不能冒充一个可跟踪 syscall。
ARM64 缺少 open/stat/lstat/pipe/poll/select/fork/vfork/dup2/epoll_wait/arch_prctl/getdents 等；应由 openat/newfstatat/pipe2/ppoll/pselect6/clone/dup3/epoll_pwait/getdents64 覆盖相应操作。

| syscall | amd64 | arm64 |
| --- | ---: | ---: |
| read / write | 0 / 1 | 63 / 64 |
| close / openat | 3 / 257 | 57 / 56 |
| readlinkat | 267 | 78 |
| clone / clone3 | 56 / 435 | 220 / 435 |
| execve / execveat | 59 / 322 | 221 / 281 |
| socket / connect / accept | 41 / 42 / 43 | 198 / 203 / 202 |
| dup / fcntl / ioctl | 32 / 72 / 16 | 23 / 25 / 29 |
| futex / epoll_pwait | 202 / 281 | 98 / 22 |

### 4. ABI-layout assumptions

这里的 N 限于两种 little-endian native LP64 ABI，绝不表示任意架构。静态布局一致不等于已通过 ARM64 native capture tests。

| 分类 | 类别与 owner | 判断 / 后续证据 |
| --- | --- | --- |
| N | path/readlink，path/readlink capture helpers | 字节串和显式长度；指针均 64-bit。syscall availability 仍需分架构。 |
| H | stat，`syscall_stat_direct_event_v2.h`、`type_stat.go`、`format_socket.go` | 固定 144 字节和 x86 字段偏移；ARM64 stat 为 128 字节，nlink/mode/uid/gid/rdev/blksize 等不同。 |
| N | statx | 固定宽度 UAPI，256 字节；保留已捕获字段范围和版本约束。 |
| N | openat2/clone3 | UAPI u64 字段，open_how/clone_args 显式 size；无须人为复制布局。 |
| H | clone metadata | 原始 clone 的 tls/child_tid 参数顺序有差异；flags 首参数共用不代表完整签名共用。 |
| N | iovec | pointer + size_t，各 8 字节，16 字节 stride。 |
| N | msghdr/mmsghdr/cmsghdr | native LP64 56/64/16 字节，指针与 size_t 8 字节；需 target 编译断言验证所有偏移。 |
| N | sockaddr | 已解码 AF_UNIX/INET/INET6/NETLINK 布局可共用；网络字段使用网络字节序。 |
| N/U | fcntl | native flock 32 字节，cmd/O_* 需分别审计；共享布局不覆盖所有命令语义。 |
| H | open flags / xlat | x/sys 共有常量中 O_DIRECT、O_DIRECTORY、O_NOFOLLOW、O_TMPFILE 不同；host gcc 生成会污染目标表。 |
| N/U | ioctl | 两架构使用 asm-generic IOC 位编码；具体命令结构、可用性仍按命令核实。固定 TCGETS/TCSETS 60 字节需对照 kernel termios，不能用 libc termios 代替。 |
| N | poll/select | pollfd=8，native long fd_set、timespec/timeval 为 LP64；ARM64 用 ppoll/pselect6。 |
| H | epoll | x86 packed event=12/data offset=4；ARM64 event=16/data offset=8；捕获、nested FD 扫描、Go 解码、长度截断必须一起修。 |
| N | timespec/timeval/itimers/timex | native 64-bit 字段，可保持共同 decoder；旧 32-bit time ABI 不支持。 |
| N/U | futex | u32 futex word、固定 futex_waitv、native timeout 布局；需 target semantic fixtures。 |
| N/U | quota | 通用和 XFS 用户 ABI 固定宽度/LP64；现有人工 size/offset 需 target 静态验证，不以 CO-RE 当证明。 |
| A/U | namespace | 内核对象通过 CO-RE，用户 snapshot 为自有固定宽度 ABI；helper/tracepoint capability 需本机探测。 |
| N/U | AIO | iocb/io_event 固定宽度，context/指针在本阶段 64-bit；验证 target arity 和偏移。 |
| N/U | BPF syscall | bpf_attr 固定宽度与 aligned_u64；kernel-side metadata、命令可用性、nested 字段需要 capability 测试。 |
| H/U | KVM ioctl | 通用 IOC 不代表 x86 KVM commands、register structs、tracepoints 在 ARM64 有效；未验证增强项必须明确拒绝/降级。 |
| N/U | signal | native sigset/stack 和 sigaction 需对照目标 UAPI；compat signal return 必须先排除。 |
| A/H | dirents/arch_prctl | dirent64 布局可共享；旧 getdents 和 arch_prctl 只应存在于 amd64 metadata，当前注释/注册未表达边界。 |

### 5. generated-code assumptions

| 分类 | 位置 | 发现与影响 |
| --- | --- | --- |
| H | `bpf*_bpfel.go` | tags 接受 amd64/arm64/386/arm/riscv64 等，嵌入同一 syscall ABI object。 |
| H | `bpf*_bpfeb.go` | 大端文件暗示不曾验证的架构；本阶段没有 big-endian 支持目标。 |
| A/U | `bpf/vmlinux.h` | 单套 x86 BTF type dump；CO-RE 可迁移公共内核字段，但不能修复用户布局、缺失字段和 syscall 宏。 |
| H | `generate-syscalls/btf.go` | BTF function prefix 识别 __x64_sys_，缺 __arm64_sys_；生成读取宿主 live BTF/tracefs。 |
| H | `generate-xlats/generator.go` | 编译执行 host gcc 小程序，且编译错误后继续，可能丢常量；不是 deterministic cross generator。 |
| A | event ABI / capture manifest generators | 自有定宽合同和名称路由适合共享，已有 -check 模式可扩展。 |
| U | artifact 管理 | BPF .o 被 ignore，Go 文件 embed .o；需验证 clean checkout 的构建路径并修正文档承诺。 |

### 6. test assumptions

| 分类 | 位置 | 发现与影响 |
| --- | --- | --- |
| H | `test/run_tests.py` | STRACE_ARCH/STRACE_NATIVE_ARCH 固定 x86_64；SIZEOF_LONG=8 仅在明确 native LP64 后才合理。 |
| H | `test/ebpf_semantic_checks.py` | 强制 stat/lstat/arch_prctl/pipe/getdents，fstat 固定 144；在 ARM64 必须按 availability 和 ABI oracle 调整。 |
| H | Go payload/route fixtures | 大量 synthetic ID 使用 amd64 literal，可能验证错误 handler；需要目标名称查表与独立双架构 oracle。 |
| A/U | native ARM64 runner | CI 使用 `ubuntu-24.04-arm` 执行 ARM64 build/unit；当前仍未配置 ARM64 privileged semantic suite，不能把 build/unit 当作完整 native tracing 验证。 |
| N | 源码策略、event-v2 envelope tests | 自有 wire ABI 可共享；架构影响的 source assertions 需同步更新。 |

审计基线实测：`GOCACHE=/tmp/strace-go-gocache go test ./...` 全通过；当时
`sudo -n id -u` 返回 0。
编译 core/recvmsg 无 libc multiarch include 通过。尚未在本阶段运行 root semantic 或 ARM64 tests。

### 7. documentation assumptions

| 分类 | 位置 | 发现与影响 |
| --- | --- | --- |
| H | README 环境要求 | Linux+BTF 描述过宽，无 native ABI support matrix。 |
| A | `doc/arch.md` | 已明确主要生成/验证目标 x86_64，正确区分大端 binding 与语义支持。 |
| H | README 构建章节 | 声称已有产物即可普通构建，未说明 ignored .o 与双目标 regeneration。 |
| U | 验证状态 | 必须按 build、BPF compile、metadata semantics、native runtime 分列，不能以 cross build 代替 native evidence。 |

## ADR：目标模型与方案比较

1. 运行期加载双 syscall/ABI 表：可单进程选择目标，但扩大控制面和 hot path 状态，仍无法修复编译进 BPF 的常量；不选。
2. 生成期确定目标，公共名称语义 + 目标号码/真实 ABI 差异：改动集中、tags 可验证、无每次 syscall 的架构分支；选择。

1. 为每个 target 使用 libc multiarch/sysroot：方便引入系统头，但交叉环境依赖大，容易误用宿主头；不选默认路径。
2. vmlinux CO-RE + libbpf helper + 项目明确 ABI 定义：现有依赖扫描支持此方案；选择，真实架构差异集中定义。

1. 双目标都读取当前机器 BTF/tracepoint 生成参数：改动少但不确定、可能把 host clone 签名写到 target；不选。
2. 提交按名称审计的参数 schema，目标 numbers 来自固定 x/sys，live BTF 保留审计用途：可复现且 target 明确；选择。

预期 owner：`internal/architecture` 负责目标选择、Go/compiler 映射、native ABI 合同；metadata generator 负责 syscall identity；capture manifest 继续负责名称→program slot；BPF generator 统一选择 target 和 object；共同引擎不新增 factory/plugin。

假设：本阶段两目标均 little-endian native LP64；目标架构参数优先于 GOARCH，再使用 host 默认。
原生运行必须校验 Go target、内核架构、metadata、BPF artifact；不允许把 ARM64 build support 写成 native semantic validation。
不支持的 target 在构建或启动边界明确失败；compat syscall 在 native route/decode 前识别并报告，覆盖跟踪期间 exec ABI 转换。

## 实施与验收计划

1. Phase 2：统一目标模型与生成入口，移除散落 include；为每个目标选择 Go/BPF artifact；target precedence 和 unsupported tests。
2. Phase 3：固定输入生成双架构 metadata、C numbers，检查 unavailable syscall 与 manifest；双目标 ID→semantic handler、filter/lifecycle tests。
3. Phase 4：stat/epoll/open constants/clone/recvmsg 的真实差异；其余布局用 target UAPI 编译断言；compat 在 dispatch 前保护。
4. Phase 5：amd64/arm64 全部 BPF collection 和 Go build，重复生成比较；检测错误 artifact。
5. Phase 6：amd64 root semantic、小范围 upstream 和 small；ARM64 使用 native runner 做 build/unit，privileged semantic 缺口保持明确；新增可移植 semantic fixtures。
6. Phase 7：CI build/test/generation matrix、README support matrix、开发者 native/cross 命令及实际验证结果。

参考：
- https://github.com/torvalds/linux/blob/master/include/trace/events/syscalls.h
- https://github.com/torvalds/linux/blob/master/include/uapi/linux/eventpoll.h
- https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/thread_info.h
- https://github.com/torvalds/linux/blob/master/arch/arm64/include/asm/thread_info.h
- 项目固定依赖 `golang.org/x/sys v0.47.0` 的 zsysnum/zerrors/ztypes_linux_{amd64,arm64}.go。

## 实施结果（Phase 2–7）

目标模型由 `internal/architecture` 持有。它只接受 Go 名称 `amd64`、`arm64`，并
提供到 Linux 名称 `x86_64`、`aarch64`、BPF wrapper 前缀和运行时校验的显式映射。
生成脚本的目标优先级是命令行参数、环境 `ARCH/GOARCH`、宿主默认值；不支持的目标
在 Makefile、生成器和程序启动处都返回带支持列表的错误。

syscall metadata 由名称/参数 schema、semantic catalog 和固定版本 `x/sys` 号码
合并生成。每个目标有独立 Go 表和 C `SYS_*` header，header selector 只按 clang 的
`__TARGET_ARCH_x86` 或 `__TARGET_ARCH_arm64` 选择。route map 在生成期消费当前表，
因此缺失的 ARM64 syscall 不会被当成另一个号码；双表测试覆盖 read、write、close、
openat、readlinkat、clone、clone3、execve、socket、connect、dup、fcntl、ioctl、
futex 和 epoll_pwait 等代表调用。

BPF generation 的唯一入口是 `scripts/generate-bpf.sh` / `make generate-bpf`。所有
collection 使用 `bpf2go -target amd64|arm64` 和项目头，不再散落
`/usr/include/x86_64-linux-gnu`。生成输出包含 target 和 Linux architecture，且
每个 collection 在加载前校验 metadata ABI hash；重复 ARM64 生成的 object SHA-256
在本次验证中一致。bpf2go 对 x86 默认产生的 `(386 || amd64)` userspace tag
由统一入口规范为 `linux && amd64`，因此 generated artifact 也不会暴露 32-bit
伪支持。

真实 ABI 差异集中在 `internal/architecture/layout_linux.go`、
`bpf/native_abi_layout.h` 和目标 xlat 表：amd64 stat/epoll 分别为 144/12 字节，
arm64 为 128/16 字节；epoll data offset 为 4/8；native open flags、termios 和
clone 参数也按目标生成。iovec、msghdr、cmsghdr、sockaddr、timespec/timeval、
statx、open_how、flock 等在两个 native LP64 目标的 layout contract 中确认一致，
没有为了文件对称性引入伪架构分支。

syscall observation path 继续使用 `tracepoint/raw_syscalls/sys_enter` 和
`tracepoint/raw_syscalls/sys_exit` 的 `id`、`args[6]`、`ret` 字段，因此不读取
userspace calling convention 的寄存器。只有 recvmsg kretprobe 需要返回寄存器，
它通过 `native_kretprobe_return` 和目标 wrapper symbol 显式分支处理。

compat 边界在 BPF native dispatch 前检查：x86_64 的 compat task 和 x32 syscall、
ARM64 的 32-bit task 都发出 `unsupported_abi` 终止事件；userspace 不会继续使用
native decoder。amd64 上用 `int 0x80` fixture 实际验证了 fail-fast；32-bit ARM
compat binary 尚未声称支持。

### 验证证据

已运行：

```text
GOCACHE=/tmp/strace-go-gocache go test ./...
go run ./cmd/generate-syscalls -arch all -check
go run ./cmd/generate-capture-manifest -check
make generate-bpf ARCH=amd64
make generate-bpf ARCH=arm64
make build ARCH=arm64
```

amd64 native root smoke 覆盖 openat、close、read/write 和兼容 ABI 拒绝；完整
`ebpf-semantic` suite 由 CI 的 privileged amd64 job 执行。ARM64 build/unit job
使用 GitHub 的 native `ubuntu-24.04-arm` runner，workflow 不安装或调用 QEMU；本地
x86_64 开发机只完成 ARM64 的交叉构建、生成和 metadata/route 静态验证。ARM64
privileged BPF load、路径/生命周期/FD-state semantic suite 仍是明确的验证缺口，
必须在匹配的 native ARM64 Linux host 上执行后才能扩大支持声明。
历史 BPF source gates 中仍有按 amd64 数字字面量检查的静态契约；它们已显式使用
`//go:build amd64`，ARM64 使用独立的 target metadata、ABI contract 和 dispatcher
route tests，避免把 amd64 source fixture 当成 ARM64 语义证据。
`test/ebpf_semantic_checks.py` 的固定结构尺寸和 `arch_prctl` 断言同样属于 amd64
privileged contract；在 ARM64 runner 上不能直接复用，必须先改成 target-aware
expectations 并通过 native load/semantic suite 后才能扩大 ARM64 的验证声明。

当前不支持 KVM vCPU exit-reason 的 ARM64 解码、32-bit compat ABI、x32 以及其他
Linux 架构。增加第三个架构时，只需增加 `internal/architecture` target、目标
syscall table/header、真实 ABI contract、BPF build target、route/metadata tests 和
CI runner；共同 tracing engine 不应加入散落的架构条件分支。
