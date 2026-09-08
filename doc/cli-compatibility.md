# CLI 兼容性契约

本文档记录 `--help` 功能与纯 eBPF 产品架构之间的边界，并作为 CLI
兼容工作的验收矩阵。下表以当前代码、快速门禁和已登记的 upstream 用例为准；
“应实现”只保留仍需按纯 eBPF 路径闭环的能力。

基线日期：2026-09-08。

## 状态定义

- **已闭环**：解析、immutable policy、运行时/输出路径和回归验收均已完成；若 upstream
  断言 ptrace 专属细节，则以本地纯 eBPF 合同测试作为验收依据。
- **应实现**：不改变纯 eBPF 产品路径，必须补齐解析、运行时行为和 upstream 测试。
- **架构原生差异**：功能存在，但数据来源决定其语义与 ptrace `strace` 不完全相同；
  必须提供当前架构的运行时证据并明确 upstream XFAIL。
- **架构冲突**：实现会引入 ptrace stop、tracee 内存修改或无意义的 ptrace 优化开关；
  当前产品必须明确拒绝，不能静默接受。

## 功能矩阵

| 功能域 | 参数 | 目标状态 | 验收依据 |
| --- | --- | --- | --- |
| 启动 | `-E/--env`、`-p/--attach` | 已闭环 | `strace-E*`、`strace-p`、attach tests |
| 启动 | `-u/--user`、`--argv0` | 已闭环 | `strace--argv0`、credential parser/runtime tests |
| 追踪 | `-b/--detach-on=execve` | 已闭环 | `status-detached*`、exec lifecycle regression |
| 追踪 | `-D/-DD/-DDD/--daemonize` | 架构冲突 | upstream 契约依赖 `/proc/*/TracerPid` 的 ptrace 父子关系 |
| 追踪 | `-f/--follow-forks`、`-ff/--output-separately` | 已闭环 | `fork-f`、`vfork-f`、`strace-ff` |
| 追踪 | `--kill-on-exit` | 已闭环 | parser tests 加 `TestKillOnExitTerminatesTraceCommand` |
| 追踪 | `-I/--interruptible` | 架构冲突 | 该选项控制 ptrace wait/解码期间的 signal blocking |
| 过滤 | `trace`、syscall class、regex | 已闭环 | `qual_syscall`、`filtering_syscall-syntax` |
| 过滤 | ABI designator（`@64/@32/@x32`） | 架构原生差异 | selector syntax/qualification tests；非 native tracee decode 尚未纳入纯 eBPF ABI |
| 过滤 | `signal` | 已闭环 | `qual_signal` 和 BPF signal event semantic suite |
| 过滤 | `status`、`-z/-Z` | 已闭环 | `status-*` |
| 过滤 | `trace-fds`、`-P/--trace-path` | 已闭环 | `*-P`、trace-fds tests |
| 输出 | `-a`、color、abbrev/verbose/raw、quiet | 已闭环 | `strace-a*`、`qual_syscall`、format/output tests |
| 输出 | `read/write` | 架构原生差异 | bounded snapshot tests；`read-write.gen.test` 具名 XFAIL |
| 输出 | `kvm=vcpu`、namespace、decode-fds | 已闭环 | 对应 upstream tests 与 event-snapshot semantic tests |
| 输出 | `kvm=vcpu+` 完整 `kvm_run` | 架构冲突 | 需要发现并读取 tracee 的共享 mmap，违反当前 bounded snapshot 边界 |
| 输出 | `-i`、`-n`、`-N` | 已闭环 | `pc.test`、`strace-n` 加 arg-name focused tests |
| 输出 | `-o/-A/--output-separately` | 已闭环 | `strace-A`、`strace-ff`、output tests |
| 输出 | timestamps、string/hex/xlat formats | 已闭环 | `strace-r/t/tt/ttt/T/x/xx` 和 `*-X*` |
| 输出 | `-y/-yy` | 已闭环 | `*-y`、`*-yy`；未知 attach 前状态保持 unknown |
| 输出 | `-k` 地址栈 | 已闭环 | BPF stack semantic test |
| 输出 | symbol/source/demangle stack | 架构冲突 | 当前契约不读取 tracee mapping 或 ELF 做事后符号化 |
| 输出 | decode-pids、always-show-pid | 已闭环 | `strace--decode-pids-*`、always-show-pid tests |
| 统计 | `-c/-C/-S/-U` | 已闭环 | `strace-C/S`、summary tests；`strace-c` 的非 `-O` 分支 |
| 统计 | `-w` | 已闭环 | CPU/wall 双时钟运行时回归；`strace-cw` 的非 `-O` 分支 |
| 统计 | `-O/--summary-syscall-overhead` | 架构冲突 | 不存在需要扣除的 ptrace syscall-stop overhead |
| 停止 | `--syscall-limit` | 已闭环 | `strace--syscall-limit*` |
| 修改 | `inject`、`fault`、delay、poke | 架构冲突 | 需要修改 syscall 结果、时序、signal 或 tracee 内存 |
| 杂项 | `-d/--debug` | 已闭环（eBPF runtime debug） | `nsyscalls-d` 加本地 debug contract；不伪造 ptrace diagnostics |
| 杂项 | `--seccomp-bpf` | 架构冲突 | eBPF syscall filter 已在 probe 入口执行，无 ptrace stop 可优化 |
| 杂项 | `--tips`、`-h`、`-V` | 已闭环 | `strace--tips*`、help/version tests |

## 当前闭环证据

当前实现已经把可由纯 eBPF 完成的 CLI 路径接通：参数解析进入 immutable policy，policy
再进入 BPF 过滤、生命周期状态和用户态输出；重复 descriptor `!`、非 leader exec
handoff、零返回 iovec、suspended probe 的 status 过滤和稀疏继承 fd 均有回归覆盖。

本轮门禁包括：

- `GOCACHE=/tmp/strace-go-gocache go test ./...`；
- `./build.sh`（重新生成并编译 BPF/元数据）；
- 已登记的 `more` upstream suite：265 项中 262 PASS、0 FAIL、2 个具名 XFAIL、
  1 个非契约 XPASS-ALLOWED；
- root 下 `--kill-on-exit`、`-u`、`-b` 的真实运行回归。

`options-syntax.test` 和 upstream `kill-on-exit.test` 不作为纯 eBPF exact gate：前者还
断言 `--secontext` 等本产品明确不提供的 ptrace/SELinux 诊断，后者寻找
`PTRACE_O_EXITKILL` 标记而不是验证实际退出信号行为。对应行为由本地 parser/runtime
测试覆盖，不能用伪造诊断把架构差异标成通过。

`--stack-trace-frame-limit` 适用于现有纯 eBPF 地址栈：默认上限为 256，用户态输出在
指定帧数后截断。`strace-k-with-depth-limit.test` 还强制断言 tracee ELF 符号与精确
ptrace signal-stop 栈，因此只登记为具名 XFAIL；地址帧截断由 event-snapshot semantic
测试负责，不以 procfs/ELF fallback 消除该差异。

## 当前 ABI designator 边界

`@64`、`@32` 和 `@x32` 已进入统一 syscall selector parser：native personality
表达式参与当前 syscall 集，并在 BPF 入口严格丢弃不在生成元数据中的 syscall ID；受支持的
非 native personality 表达式会完成名称、类别、编号和正则校验，但不会改变 native syscall
集。普通（未带 `@PERSONALITY`）选择器仍保留未知 syscall 诊断，以兼容 `nsyscalls*` 行为。
该阶段不代表已经支持 compat tracee 解码。

完整的非 native tracing 仍需 event ABI 携带 personality，并由生成器提供对应 syscall
元数据表；在这些运行时合同完成前，不能把非 native selector 伪装为 native selector。
当前合同由 `filtering_syscall-syntax.test`、`trace_personality_*` 和 `nsyscalls*` 用例覆盖。

因此，ABI designator 的“应实现”部分已经闭环为语法、名称/类别/编号/正则校验和 native
过滤；非 native tracee 的完整解码是单独的 ABI 扩展，不把它伪装成已经完成的兼容能力。

## 实施规则

1. 未知、缺值、非法或架构冲突参数必须返回具体错误，不能静默忽略。
2. 每个应实现参数必须完成 `CLI -> immutable policy -> runtime/output` 的单路径传播。
3. 每个阶段先增加失败回归，再实现，再运行精确 upstream 测试和快速 Go 门禁。
4. runner 只登记当前 upstream 子模块真实存在且已通过的测试；不存在的测试名不算覆盖。
5. 纯 eBPF 固有限制必须记录为具名 XFAIL，不能用 ptrace、procfs 或 process-vm fallback 消除。
