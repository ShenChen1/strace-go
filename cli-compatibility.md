# CLI 兼容性契约

本文档记录 `--help` 功能与纯 eBPF 产品架构之间的边界，并作为 CLI
兼容工作的验收矩阵。它描述目标状态，不代表所有“应实现”项目当前已经完成。

基线日期：2026-08-27。

## 状态定义

- **应实现**：不改变纯 eBPF 产品路径，必须补齐解析、运行时行为和 upstream 测试。
- **架构原生差异**：功能存在，但数据来源决定其语义与 ptrace `strace` 不完全相同；
  必须提供当前架构的运行时证据并明确 upstream XFAIL。
- **架构冲突**：实现会引入 ptrace stop、tracee 内存修改或无意义的 ptrace 优化开关；
  当前产品必须明确拒绝，不能静默接受。

## 功能矩阵

| 功能域 | 参数 | 目标状态 | 验收依据 |
| --- | --- | --- | --- |
| 启动 | `-E/--env`、`-p/--attach` | 应实现 | `strace-E*`、`strace-p`、attach tests |
| 启动 | `-u/--user`、`--argv0` | 应实现 | `options-syntax`、`strace--argv0` |
| 追踪 | `-b/--detach-on=execve` | 应实现 | `options-syntax` 加 exec lifecycle 回归 |
| 追踪 | `-D/-DD/-DDD/--daemonize` | 应实现 | `strace-D/DD/DDD` |
| 追踪 | `-f/--follow-forks`、`-ff/--output-separately` | 应实现 | `fork-f`、`vfork-f`、`strace-ff` |
| 追踪 | `--kill-on-exit` | 应实现 | `options-syntax` 加真实信号回归 |
| 追踪 | `-I/--interruptible` | 架构冲突 | 该选项控制 ptrace wait/解码期间的 signal blocking |
| 过滤 | `trace`、syscall class、regex、ABI designator | 应实现 | `qual_syscall`、`qualify_personality*` |
| 过滤 | `signal` | 应实现 | `qual_signal` 和 BPF signal event semantic suite |
| 过滤 | `status`、`-z/-Z` | 应实现 | `status-*` |
| 过滤 | `trace-fds`、`-P/--trace-path` | 应实现 | `options-syntax`、`*-P` |
| 输出 | `-a`、color、abbrev/verbose/raw、read/write、quiet | 应实现 | `options-syntax`、`qual_syscall`、read/write tests |
| 输出 | KVM、namespace、decode-fds | 应实现 | 对应 upstream tests 与 event-snapshot semantic tests |
| 输出 | `-i`、`-n`、`-N` | 应实现 | `strace-n` 加 IP/arg-name focused tests |
| 输出 | `-o/-A/--output-separately` | 应实现 | `strace-A`、`strace-ff`、output tests |
| 输出 | timestamps、string/hex/xlat formats | 应实现 | `strace-r/t/tt/ttt/T/x/xx` 和 `*-X*` |
| 输出 | `-y/-yy` | 应实现 | `*-y`、`*-yy`；未知 attach 前状态保持 unknown |
| 输出 | `-k` 地址栈 | 应实现 | BPF stack semantic test |
| 输出 | symbol/source/demangle stack | 架构冲突 | 当前契约不读取 tracee mapping 或 ELF 做事后符号化 |
| 输出 | decode-pids、always-show-pid | 应实现 | `strace--decode-pids-*`、always-show-pid tests |
| 统计 | `-c/-C/-S/-U` | 应实现 | `strace-c/C/S`、count tests |
| 统计 | `-w` | 架构原生差异 | eBPF duration 原生为 wall clock；`strace-cw` |
| 统计 | `-O/--summary-syscall-overhead` | 架构冲突 | 不存在需要扣除的 ptrace syscall-stop overhead |
| 停止 | `--syscall-limit` | 应实现 | `strace--syscall-limit*` |
| 修改 | `inject`、`fault`、delay、poke | 架构冲突 | 需要修改 syscall 结果、时序、signal 或 tracee 内存 |
| 杂项 | `-d/--debug` | 应实现为 eBPF runtime debug | 本地 debug contract；不伪造 ptrace diagnostics |
| 杂项 | `--seccomp-bpf` | 架构冲突 | eBPF syscall filter 已在 probe 入口执行，无 ptrace stop 可优化 |
| 杂项 | `--tips`、`-h`、`-V` | 应实现 | `strace--tips*`、help/version tests |

## 实施规则

1. 未知、缺值、非法或架构冲突参数必须返回具体错误，不能静默忽略。
2. 每个应实现参数必须完成 `CLI -> immutable policy -> runtime/output` 的单路径传播。
3. 每个阶段先增加失败回归，再实现，再运行精确 upstream 测试和快速 Go 门禁。
4. runner 只登记当前 upstream 子模块真实存在且已通过的测试；不存在的测试名不算覆盖。
5. 纯 eBPF 固有限制必须记录为具名 XFAIL，不能用 ptrace、procfs 或 process-vm fallback 消除。
