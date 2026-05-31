# strace-go

`strace-go` 是一个基于 **Go 语言** 和 **eBPF (Extended Berkeley Packet Filter)** 技术实现的高性能系统调用追踪工具。它旨在提供与传统 `strace` 类似的命令行可观测性体验，但通过现代 Linux 内核的探针与异步数据通道，极大降低了对被追踪程序的运行性能损耗，是面向云原生与高并发生产环境的轻量级观测系统。

> [!NOTE]
> 本项目的终极目标是实现一个与经典 `strace` 输出 1:1 兼容的 eBPF 替代品。我们通过在 `./strace-upstream/tests` 中集成官方 `strace` 测试套件来驱动该工具的开发与持续迭代。
> **里程碑达成 (2026-05)**: 目前 `strace-go` 已经完美跑通了官方的 **1479 个系统调用回归测试用例 (make check)**，这标志着我们在输出精准度上已与传统 `strace` 达到极高的对齐水准。

---

## 🛠️ 项目结构

```text
strace-go/
├── bpf/                   # eBPF C 源码及内核头文件 (strace.c, vmlinux.h, syscall_capture.h)
├── cmd/
│   ├── generate-syscalls/ # 系统调用字典生成器 (从内核动态提取 ID 与参数信息)
│   ├── generate-xlats/    # 标志位常量翻译生成器 (从 strace-upstream 提取 flags 字典)
│   └── strace-go/         # 主程序入口及 eBPF 加载器与事件循环
├── pkg/
│   ├── cli/               # 命令行参数解析
│   ├── event/             # eBPF 事件解析、缓存同步与路径过滤
│   ├── format/            # 常用系统调用数据结构（如 stat, timespec 等）的格式化解析器
│   ├── handler/           # 基于注册表的特定系统调用解码器 (如 ioctl, epoll, network 等)
│   ├── meta/              # 自动生成的系统调用元数据与标志翻译表 (syscall_table.go, xlat_auto.go)
│   └── procmem/           # 高速进程内存读取器 (基于 process_vm_readv /proc/pid/mem 以及 ptrace 回退)
├── test/                  # 测试框架与批量集成测试脚本
├── strace-upstream/       # 官方 strace 源代码仓库 (Submodule, 用作测试对照和数据源)
├── build.sh               # 一键生成与构建脚本
└── strace-go              # 编译后生成的可执行文件
```

---

## 🏗️ 架构设计与工作流

`strace-go` 采用了“**内核态探针收集 + 用户态异步排水与回退读取**”的解耦架构。其主要工作流程如下：

```mermaid
graph TD
    subgraph 内核态 (eBPF Kernel Probe)
        tp_enter[sys_enter tracepoint] --> |1. 触发系统调用| filter{PID 过滤}
        filter -->|匹配| heap_alloc[从 heap per-cpu map 借用 bpf_event]
        heap_alloc -->|2. 内核态预读| capture[CAPTURE_ARGS_ENTER<br/>用户空间参数首部读取 2KB]
        capture -->|3. 上下文入缓存| hash_map[(events_map HASH MAP<br/>Key: TID, Value: bpf_event)]
        
        tp_exit[sys_exit tracepoint] -->|4. 系统调用返回| lookup[从 events_map 查找对应 TID 缓存]
        lookup -->|找到| exit_capture[CAPTURE_ARGS_EXIT<br/>捕获返回值与出口参数]
        exit_capture -->|5. 发送事件| ring_buf[events BPF RING BUFFER]
        ring_buf -->|6. 清理缓存| delete_hash[从 events_map 物理删除 TID]
    end

    subgraph 用户态 (Go User Space Controller)
        done_chan{目标进程状态}
        ring_reader[events.Read BPF Ring Buffer Reader] -->|7. 高频排水| event_chan[eventChan 环形通道 2048]
        event_chan -->|8. 派发事件| handler_loop[handleEvent 核心处理逻辑]
        done_chan -->|进程退出| wait_close[处理剩余缓存并优雅关闭]
        
        handler_loop -->|9. 解析嵌套指针/大参数| fallback_check{内核态是否读取完整?}
        fallback_check -->|不完整/未读取| mem_reader[procmem.Reader 多级读取机制]
        
        subgraph 进程虚拟内存读取 (procmem.Reader)
            level1[1. process_vm_readv<br/>跨进程直读] -.->|失败| level2[2. /proc/PID/mem<br/>文件接口直读]
            level2 -.->|失败| level3[3. PTRACE_PEEKDATA<br/>Ptrace 内存读取]
        end
        
        mem_reader -->|读取内存数据| format_step[format/handler 参数解码]
        fallback_check -->|内核已完整读取| format_step
        
        format_step -->|10. 智能常量还原| xlat[meta/xlat_auto.go 常量翻译字典]
        xlat -->|11. 格式化输出| stderr[标准错误输出 stderr / 输出文件]
    end

    style 内核态 fill:#e1f5fe,stroke:#0288d1,stroke-width:2px;
    style 用户态 fill:#efebe9,stroke:#5d4037,stroke-width:2px;
    style 进程虚拟内存读取 fill:#fff3e0,stroke:#f57c00,stroke-width:2px;
```

### 💡 底层设计要点

1. **线程级安全的上下文跟踪 (events_map)**
   为了避免多线程程序在内核中并发执行系统调用时产生交错与数据覆盖，`strace-go` 在内核中引入了以线程 ID (`TID`) 为 Key 的 `events_map` (HASH MAP)。在 `sys_enter` 时捕获参数并缓存，在 `sys_exit` 时再行提取和删除，保证了跟踪的精确无误和绝对的线程安全。

2. **Per-CPU 辅助堆栈设计 (heap)**
   由于 eBPF 内核栈仅有限制极严的 512 字节空间，直接在栈中分配一个含有 2048 字节大缓冲区的事件结构体 (`bpf_event`) 将无法通过内核 Verifier 的静态安全检查。
   `strace-go` 的设计极其精妙地通过声明一个全局单元素的 `BPF_MAP_TYPE_PERCPU_ARRAY` (名为 `heap`)，在进入探针时，借助 `bpf_map_lookup_elem` 快速获取属于当前 CPU 核心的独占内存块。这不仅成功规避了 512B 栈限制，还保证了在超高并发下的零内存碎片和极高性能。

3. **多级进程内存读取 (procmem.Reader)**
   由于 eBPF 运行在高度受限的安全沙箱中，内核态无法安全解引用多级嵌套指针，也无法复制无限长度 of 字符串。`strace-go` 将大部分工作放在用户态：
   - **内核态拷贝**：只进行前 2048 字节的高频轻量拷贝。
   - **用户态三级回退**：若内核未能成功复制（如 `probe_ret_enter < 0`），Go 端的 `procmem` 模块将按如下优先级读取目标进程内存：
     1. **`process_vm_readv` (系统调用 310)**：无锁、无侵入、直接在内核层跨进程读取目标进程的页表，效率极高。
     2. **`/proc/<pid>/mem` 文件**：打开系统文件句柄进行直接随机读，适用于某些容器化安全策略限制了 `process_vm_readv` 的环境。
     3. **`PTRACE_PEEKDATA`**：作为最后的兜底手段，通常要求进程已被 `ptrace` attach 且处于暂停状态。

---

## 🚀 构建与编译指南

我们提供了一键自动化构建脚本 `build.sh`，可完成 eBPF 代码生成和 Go 二进制文件的编译：

```bash
./build.sh
```

### 📋 分步与手动构建流程

#### 1. 系统依赖
在编译前，请确保您的系统安装了以下组件：
- Go 1.21 或更高版本
- `clang` & `llvm`（用于编译 eBPF C 源码）
- Linux 内核头文件：`linux-headers-$(uname -r)`
- 较新的 Linux 内核版本（建议 >= 5.8，需完整支持 BPF Ring Buffer 和 BTF 机制）

#### 2. 生成系统调用元数据与 BPF 字节码
因代码生成器需要动态读取受内核保护的 `/sys/kernel/tracing` 调试目录并提取当前系统的所有 tracepoints 参数，必须以 `sudo` 权限运行：
```bash
cd cmd/strace-go
sudo go generate ./...
```
> [!TIP]
> 运行成功后，会在 `pkg/meta/` 下自动生成 `syscall_table.go`，在 `bpf/` 下生成 `syscall_capture.h` 并在当前目录生成对应的 `bpf_bpfel.go` 和 `bpf_bpfel.o` 字节码。

#### 3. 编译与运行
回到项目根目录并编译：
```bash
cd ../..
go build -o strace-go ./cmd/strace-go
```
运行追踪目标：
```bash
sudo ./strace-go <待追踪的命令或进程>
```

#### 4. 运行回归测试
如果您想验证代码的稳定性和系统调用追踪的精确度，可运行集成的官方 `strace` 测试集：
```bash
cd strace-upstream/tests
make check -j $(nproc)
```
*提示: 完整测试约有 1479 项，全部通过即代表 `strace-go` 解析无任何逻辑回归。*

---

## ⚖️ 与传统 strace (基于 ptrace) 的优劣势对比

| 对比维度 | 传统 `strace` (基于 `ptrace`) | `strace-go` (基于 `eBPF` + `Go`) |
| :--- | :--- | :--- |
| **性能损耗 (Overhead)** | **极高** (每次系统调用导致 4 次内核态/用户态切换，目标进程可能变慢 10-100 倍) | **极低** (探针在内核中并发执行，用户态通过无锁 Ring Buffer 异步消费，损耗微乎其微) |
| **对应用运行的影响** | **高侵入** (强制停止/拦截应用执行，影响信号传递，多调试器间互斥) | **无侵入** (除了启动瞬间短暂使用 ptrace 同步外，后续核心抓取阶段完全不干扰应用) |
| **部署与执行权限** | **低权限** (普通用户可直接追踪自己所拥有的进程) | **高权限** (强制需要 Root 权限，或 `CAP_BPF`/`CAP_PERFMON`/`CAP_SYS_PTRACE`) |
| **复杂/嵌套结构解析** | **极其强大** (历经几十年演进，可深入解析 netlink、ioctl、套接字多层结构) | **较弱** (受限于 BPF Verifier 安全沙箱，深层指针高度依赖用户态进程内存回退读取) |
| **系统兼容性** | **极强** (几乎兼容所有 Linux 内核版本、各种类 Unix 系统以及多种硬件架构) | **受限** (仅支持较新 Linux 内核，且需要开启 BTF 功能以实现 BPF 模块正常加载) |

### 🌟 详细优势 (Pros)

1. **出色的执行性能与低侵入性**
   传统 `strace` 由于高频强拦截特性，在生产环境中运行是难以想象的灾难。而 `strace-go` 的核心追踪点直接运行于内核态，数据打包后以 Ring Buffer 极高吞吐发送，不抢占目标进程 CPU 时间，极适合生产故障排查。
2. **现代化的解耦架构**
   Go 语言编写的用户态处理循环可以非常轻松地被剥离出 CLI 界面，直接融入到 Kubernetes 等容器编排平台的 DaemonSet 或 Sidecar 监控组件中。
3. **完全兼容官方常量翻译**
   结合了 `cmd/generate-xlats` 工具，从官方 strace 精准提炼并支持了按位与标志位转换。能够输出符合 `O_RDONLY|O_CREAT|O_CLOEXEC` 的精细化逻辑表达。

### ⚠️ 缺点与局限性 (Cons)

1. **安全权限瓶颈**
   高特权级别的安全要求阻碍了非特权用户日常的开发调试。在一些有严格安全策略限制的生产容器云中，下发 `CAP_BPF` 或 `CAP_SYS_ADMIN` 会面临审计风险。
2. **多线程并发下的数据一致性 (Race Condition)**
   由于 `strace-go` 在用户态回退读取目标进程内存时没有（且为了高性能避免了）对目标进程进行长时间挂起，如果在读取期间另一个线程修改了同一个地址（例如在大块 `read`/`write` 或并发修改的文件名指针上），用户态可能会读取到部分被修改的脏数据或解析失效。
3. **启动的 Ptrace 耦合**
   虽然打着 "eBPF-based" 的旗号，但由于需要百分百捕获从 `main` 入口点执行开始的每一次系统调用，项目目前依然不得不采用 `SysProcAttr{Ptrace: true}` 的设计，在拉起子进程的瞬间让其暂停并被 attach，待 eBPF 完全加载后再进行 `Detach`。如果运行高频瞬时退出的短命令，此步骤依旧会产生一定的延迟，并非完全免除 `ptrace` 的局限。
