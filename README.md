# strace-go

`strace-go` 是一个基于 Go 语言和 eBPF 技术实现的系统调用追踪工具。它旨在提供与传统 `strace` 相似的功能，但在底层实现机制上采用了现代的内核可观测性技术。

## 项目结构

```text
strace-go/
├── bpf/                   # eBPF C 源码及内核头文件 (strace.c, vmlinux.h, syscall_capture.h)
├── cmd/
│   ├── generate-syscalls/ # 系统调用字典生成器 (从内核动态提取 ID 与参数信息)
│   ├── generate-xlats/    # 标志位常量翻译生成器 (从 strace-upstream 提取 flags 字典)
│   └── strace-go/         # 主程序入口及 eBPF 加载器
├── pkg/
│   ├── cli/               # 命令行参数解析
│   ├── event/             # eBPF 事件解析与字符串解码
│   ├── format/            # 系统调用数据结构与标志位格式化
│   ├── meta/              # 生成的元数据包 (syscall_table.go, xlat_auto.go)
│   └── procmem/           # 进程内存读取 (支持 ptrace fallback)
├── test/                  # 测试用例与批量回归测试脚本
├── strace-upstream/       # 官方 strace 仓库 (作为数据源及测试参照的 Submodule)
├── build.sh               # 自动化生成与构建脚本
└── strace-go              # 编译后生成的可执行文件
```

## 技术特点

1. **核心追踪基于 eBPF**: 利用 Linux 内核的 `tracepoint/raw_syscalls/sys_enter` 和 `sys_exit` 追踪点捕获系统调用，取代了传统 `ptrace` 的高频拦截机制。目前仅在进程启动瞬间巧妙使用一次 `ptrace` 进行生命周期同步，确保不漏抓任何早期事件。
2. **异步事件传输**: 使用 eBPF Ring Buffer 将内核捕获的系统调用事件高效、低延迟地批量传输到用户空间进行解析。
3. **动态与智能的元数据生成**: 提供独立的生成器 (`cmd/generate-syscalls`)：
   - 结合内核 `/sys/kernel/tracing/events/syscalls` 与 `gcc` 预处理器的宏解析，动态提取完全匹配当前操作系统的系统调用编号及参数字典。
   - 内置智能参数翻译机制 (`SyscallArgXlatMap`)，能将数值型的标志位（如 `flags`）智能转换为易读的宏定义组合（如 `O_RDONLY|O_CREAT`）。
4. **混合内存读取策略**: 
   - 对于少量的基础参数，直接在 eBPF 中通过 `bpf_probe_read_user` 捕获。
   - 对于超大缓冲区（如 `read`/`write` 的大数据）或深层嵌套指针，通过向进程发送 `SIGSTOP` 暂停执行，利用 `/proc/<pid>/mem` 进行回退读取，兼顾了 eBPF 验证器 (Verifier) 的安全限制与数据的完整性。

## 构建与编译指南

我们提供了一个便捷的自动化脚本 `build.sh` 来完成所有的生成与构建工作：

```bash
./build.sh
```

如果您希望了解底层构建逻辑或手动分步构建，流程如下：

### 1. 环境依赖
在编译前，请确保您的系统已安装了 `clang`、`llvm` 编译器，以及 eBPF 开发相关的内核头文件（例如 `linux-headers-$(uname -r)`）。

### 2. 生成 Syscall Table 与 eBPF 字节码
由于生成器需要读取受保护的内核目录 `/sys/kernel/tracing/events/syscalls`，因此必须使用 `sudo` 权限执行生成过程。

```bash
cd cmd/strace-go
sudo go generate ./...
```
*执行成功后，会在 `pkg/meta/` 生成包含当前内核数百个系统调用的 `syscall_table.go`，在 `bpf/` 生成相应的捕获宏 `syscall_capture.h`，并生成后端的 BPF Go 代码。*

### 3. 编译二进制程序
元数据及 BPF 字节码生成完毕后，返回项目根目录进行常规的 Go 编译：

```bash
cd ../..
go build -o strace-go ./cmd/strace-go
```

编译完成后，由于 eBPF 的权限要求，您可以加上 `sudo` 来运行该程序：
```bash
sudo ./strace-go <需要追踪的命令>
```

---

## 与传统 strace (基于 ptrace) 的优劣势对比

### 🌟 优势 (Pros)

1. **极低的性能开销 (Low Overhead)**
   - **原版 strace**: 依赖 `ptrace`，每次系统调用的进入和退出都需要在内核态和用户态之间进行频繁的上下文切换（通常是 4 次上下文切换/系统调用），导致被追踪程序性能出现断崖式下降。
   - **strace-go**: eBPF 探针在内核态内联执行，通过高性能无锁的 Ring Buffer 异步传输数据，对目标进程的执行阻塞极小。适合在生产环境中进行低开销的持续观测。

2. **更高的系统稳定性**
   - **原版 strace**: `ptrace` 具有强侵入性，会在每一个系统调用处拦截并干扰进程，且同一个进程只能被一个调试器附加。
   - **strace-go**: 仅在初始化时短暂使用 `ptrace` 将进程挂起，以完成 eBPF 过滤器的安全注入，随后即 `Detach` 脱离。核心追踪过程无侵入，不干扰信号处理，且不排斥其他观测工具。

3. **现代化的架构设计**
   - 纯 Go 实现的用户态逻辑天然支持高并发，且非常容易被剥离出来集成到 Kubernetes 等云原生监控体系中。

### ⚠️ 劣势与局限性 (Cons)

1. **执行权限要求更高**
   - **原版 strace**: 普通用户通常可以追踪自己拥有的进程（在非严格的 `yama` 安全配置下）。
   - **strace-go**: 依赖 eBPF，通常需要 `root` 权限，或者至少需要 `CAP_BPF` 和 `CAP_PERFMON` 等高级内核权能。

2. **深层参数与复杂协议解析较弱**
   - **原版 strace**: 历经数十年打磨，内置了极其庞大且详尽的解码器（涵盖了成百上千种复杂结构体、标志位掩码、Netlink 协议等）。
   - **strace-go**: 受限于 eBPF 验证器对循环次数和堆栈大小 (512 字节) 的严苛限制，在内核态解析深度嵌套的结构体（如复杂的 `ioctl` 参数）非常困难。目前高度依赖自动生成的类型提示。

3. **回退机制引入的竞态风险**
   - 当遇到大内存读取时，strace-go 选择发送 `SIGSTOP` 挂起进程来读取 `/proc/pid/mem`。这在某种程度上退化成了类似 `ptrace` 的停顿行为，且在多线程高并发场景下可能存在竞态条件。

4. **平台与内核版本依赖**
   - **原版 strace**: 兼容性极强，支持各种老旧系统和多种架构。
   - **strace-go**: 仅限 Linux 平台，且需要较新的内核版本以支持 BTF（BPF Type Format）和 BPF Ring Buffer 等现代特性。
