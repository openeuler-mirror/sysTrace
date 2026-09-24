# 附录：高级配置与使用

## 环境配置

### 日志配置

#### 日志落盘位置

默认路径：`/var/log/sysTrace`

```bash
export SYSTRACE_LOG_PATH=/var/log/sysTrace
```

#### 日志级别

默认级别：`INFO`

日志级别从高到低依次为：`DEBUG`、`WARN`、`INFO`、`ERROR`、`FATAL`

```bash
export SYSTRACE_LOG_LEVEL=INFO
```

### 数据存储配置

#### 采集数据落盘位置

默认路径：`/home/sysTrace`

```bash
export SYSTRACE_DUMP_PATH=/home/sysTrace
```

## 命令行工具

### 工具说明

`sysTrace_cli` 是 sysTrace 项目自带的命令行工具，用于与训练/推理任务中的 sysTrace 服务通信，控制各采集项的启停。

**使用前提：**

- 项目编译完成后，`sysTrace_cli` 位于 `build` 目录
- 需通过 `LD_PRELOAD` 将 `libsysTrace.so` 注入到推理/训练任务中
- 推理/训练任务已正常启动

### 使用方式

通过 设置`LD_PRELOAD` 环境变量将 `libsysTrace.so` 动态库加载到 AI 推理/训练任务中，从而启用 sysTrace 的数据采集功能。

```bash
export LD_PRELOAD=$LD_PRELOAD:<path-to-sysTrace>/systrace/build/libsysTrace.so
```

> **注意：** 
>
> - `<path-to-sysTrace>` 需要替换为实际的 sysTrace 项目路径
> - 编译时选择的数据格式（pb/json）会影响采集数据的格式

### 命令格式

```bash
./build/sysTrace_cli -h
```

**输出信息：**

``` bash
=========================================================
USAGE:
  sysTrace_cli <action> <plugin> [key=value ...]

ACTIONS:
  enable   Start or update a plugin's configuration
  disable  Stop a plugin and flush data to disk

COMMON PARAMETERS:
  duration=<sec>    - Capture duration in seconds (0 for infinite)

PLUGINS & SPECIFIC PARAMETERS:
  MSPTI       NVIDIA/Atlas Activity Tracing (HCCL, Kernels)
    event=<types>   - Comma-separated: marker, kernel, api

  IO          Disk and Network I/O Latency/Throughput

  CPU         CPU Utilization and Context Switch Trace

  Memory      Memory Allocation and Leak Detection

  CacheMiss   Hardware Cache Miss Rates and Memory Access Efficiency
    args=-p <pid> -e <events> --timeout <ms>- Standard perf-stat arguments for hardware event monitoring

  GIL         Python Global Interpreter Lock (GIL) Contention and Latency Trace
    pid=<pid>       - trace target python process

  Mutex       Pthread Synchronization Latency (Mutex/RWLock/Spinlock/Sem)
    pid=<pid>       - trace target process

  Ftrace      Linux Kernel Ftrace (Events, Function Graph, and Sched Tracing)
    cpu_list="0-15" - Trace specific CPUs (e.g., "0-3,5")
    events="<group>/<event>,<group>/<event>"- Enable tracepoints: irq, sched, syscalls, raw_syscalls, vmscan, compaction
    function_tracer="function_graph|function"- Set ftrace tracer (default: nop)
    func="func1 func2"- Filter kernel functions to trace (wildcards supported: "*mmap")
    func_stack_trace=1- Enable kernel stack trace for functions (use with function_tracer=function)
    event_stack_trace=1- Enable kernel stack trace for events (use with events!=null)

  Trace       A command-line interface for interacting with the Linux kernel's Ftrace subsystem to record and analyze system performance and kernel events.
    args=<args>     - trace-cmd args

EXAMPLES:
  sysTrace_cli enable MSPTI event=marker,kernel,api duration=10
  sysTrace_cli enable IO duration=10
  sysTrace_cli enable Memory duration=10
  sysTrace_cli enable CacheMiss duration=10 args="-p 12345 -e cache-miss"
  sysTrace_cli enable GIL duration=10
  sysTrace_cli enable Trace args="record -e sched sleep 5"
  sysTrace_cli disable CPU
  sysTrace_cli enable Mutex duration=10
  sysTrace_cli enable CacheMiss args=" -e branch-misses,cache-misses,cache-references --timeout 5000"
  sysTrace_cli disable CPU
  sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="syscalls/sys_enter_futex,syscalls/sys_exit_futext"
=========================================================
```

## 采集项列表

| Plugin    | 适用场景                                           | 命令示例                                                     |
| :-------- | :------------------------------------------------- | :----------------------------------------------------------- |
| HBM       | HBM事件                                            | `./sysTrace_cli enable HBM duration=10`                      |
| IO        | 磁盘和网络I/O延迟/吞吐量                           | `./sysTrace_cli enable IO duration=10`                       |
| MSPTI     | NVIDIA/Atlas活动跟踪（HCCL，内核）                 | `./sysTrace_cli enable MSPTI duration=10`                    |
| CPU       | CPU上下文切换跟踪                                  | `./sysTrace_cli enable CPU duration=10`                      |
| Memory    | 内存分配检测                                       | `./sysTrace_cli enable Memory duration=10`                   |
| GIL       | Python全局解释器锁（GIL）争用和延迟跟踪            | `./sysTrace_cli enable GIL duration=10`                      |
| CacheMiss | 硬件缓存未命中率和内存访问效率                     | `./sysTrace_cli enable CacheMiss args="-p 27638 -e branch-misses,cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,L1-icache-load-misses,L1-icache-loads --timeout 20000"` |
| Mutex     | Pthread同步延迟（互斥锁/读写锁/自旋锁/信号量）     | `./sysTrace_cli enable Mutex duration=10`                    |
| Ftrace    | Linux内核Ftrace（事件、函数图和调度跟踪）          | `./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="raw_syscalls/sys_enter,raw_syscalls/sys_exit"` |
| Trace     | trace-cmd命令行接口，用于Linux（内核Ftrace子系统） | `./sysTrace_cli enable Trace args="record -e sched sleep 5"` |

## 数据格式与使用示例

### HBM

#### 数据格式

采集 HBM 事件数据，包括内存持有情况，用于判断是否发生 HBM OOM 故障。

**数据格式：** pb/json

#### 使用示例

**采集指令：**

```bash
./sysTrace_cli enable HBM duration=10
```

> **说明：** `duration` 为采集时长，单位为秒

**执行成功后输出：**

``` bash
[ACK] /tmp/sysTrace_1868164.sock: SUCCESS
[ACK] /tmp/sysTrace_1868165.sock: SUCCESS
```

**采集结果：**

保存位置：`/home/sysTrace/hbm_trace`

**数据格式：** pb/json

```bash
-rw-r--r-- 1 root root 30900 Jan 30 09:40 hbm_trace_rank0_1868164.pb
-rw-r--r-- 1 root root 30684 Jan 30 09:40 hbm_trace_rank1_1868165.pb
```

### IO

#### 数据格式

采集磁盘和网络 I/O 延迟/吞吐量数据。

**数据格式：** pb/json

#### 使用示例

**采集指令：**

```bash
./sysTrace_cli enable IO duration=10
```

**采集结果：**

保存位置：`/home/sysTrace/io`

**数据格式：** pb/json

```bash
-rw-r--r-- 1 root root 42450 Jan 30 09:45 io_trace_rank0_1868164.pb
-rw-r--r-- 1 root root 12629 Jan 30 09:45 io_trace_rank1_1868165.pb
```

### MSPTI

#### 数据格式

采集 NVIDIA/Atlas 活动跟踪数据，包括通信算子下发/执行信息，用于判断是否发生算子慢的情况。

**数据格式：** CSV

**数据字段：**

```python
Flag,Id,Kind,Name,SourceKind,Timestamp,msptiObjectId_Ds_DeviceId,msptiObjectId_Ds_StreamId,msptiObjectId_Pt_ProcessId,msptiObjectId_Pt_ThreadId
```

#### 使用示例

**采集指令：**

```bash
./sysTrace_cli enable MSPTI event=marker,kernel,api duration=10
```

marker,kernel,api 为可选采集项

**采集结果：**

保存位置：`/home/sysTrace/mspti`

**数据格式：** CSV

```bash
-rw-r--r-- 1 root root 658179 Jan 30 09:48 mspti-marker-76.53.151.141-0.csv
-rw-r--r-- 1 root root 658179 Jan 30 09:48 mspti-marker-76.53.151.141-1.csv
```

### CPU

#### 数据格式

采集 CPU 上下文切换跟踪数据，用于判断 AI 训练中是否存在其他进程抢占 CPU 导致训练慢的问题。

**数据格式：** pb/json

**数据结构：**

```protobuf
message OSprobe {
  repeated OSprobeEntry OSprobe_entries = 1;
}

message OSprobeEntry {
  uint32 key = 1; // pid/cpuid
  uint64 start_us = 2; // 事件的开始时间
  uint64 dur = 3; // 事件的持续时间
  uint64 rundelay = 4; // cpu调度时延
  uint32 OS_event_type = 5; // 事件类型
  uint32 rank = 6; // 卡号
  string comm = 7; // 当前进程
  string nxt_comm = 8; // 即将执行的进程名字
  uint32 nxt_pid = 9; // 即将执行进程的pid
}
```

#### 使用示例

**采集指令：**

```bash
./sysTrace_cli enable CPU duration=10
```

**采集结果：**

保存位置：`/home/sysTrace/osprobe`

**数据格式：** pb/json

> **注意：** CPU 和 Memory 采集结果保存到同一个文件

```bash
-rw-r--r-- 1 root root 128010 Jan 30 09:51 os_trace_20260130_09_rank_0_1868164.pb
-rw-r--r-- 1 root root 133567 Jan 30 09:51 os_trace_20260130_09_rank_1_1868165.pb
```

### Memory

#### 数据格式

采集 CANN 层的内存数据，包括内存申请和释放的调用栈信息。

**数据格式：** pb/json

**数据结构：**

```protobuf
message ProcMem {
  uint32 pid = 1; // 线程号
  repeated MemAllocEntry mem_alloc_stacks = 2;  // 内存申请调用栈
  repeated MemFreeEntry mem_free_stacks = 3; // 内存释放调用栈
}

message MemAllocEntry {
  uint64 alloc_ptr = 1; // 内存申请起始地址
  uint32 stage_id = 2; // 训练迭代轮次
  StageType stage_type = 3; // 当前迭代阶段
  uint64 mem_size = 4; // 内存申请大小
  repeated StackFrame stack_frames = 5; // 内存申请调用栈
}

message MemFreeEntry {
  uint64 alloc_ptr = 1; // 内存释放起始地址
  uint32 stage_id = 2; // 训练迭代轮次
  StageType stage_type = 3; // 当前迭代阶段
}
```

> **注意：** Memory 和 CPU 采集结果保存到同一个文件

#### 使用示例

**采集指令：**

```bash
./sysTrace_cli enable Memory duration=10
```

**采集结果：**

保存位置：`/home/sysTrace/osprobe`

**数据格式：** pb/json

> **注意：** Memory 和 CPU 采集结果保存到同一个文件

```bash
-rw-r--r-- 1 root root 128010 Jan 30 09:51 os_trace_20260130_09_rank_0_1868164.pb
-rw-r--r-- 1 root root 133567 Jan 30 09:51 os_trace_20260130_09_rank_1_1868165.pb
```

### GIL

#### 数据格式

采集 Python 全局解释器锁（GIL）争用和延迟跟踪数据。

**数据格式：** json

#### 使用示例

##### 示例一：采集 AI 主进程 GIL 信息

默认采集运行在 NPU 卡上的主进程（可通过 `npu-smi info` 查看）

**采集指令：**

```bash
./sysTrace_cli enable GIL duration=10
```

**采集结果：**

保存位置：`/home/sysTrace/GIL`

**数据格式：** json

> **注意：** 多卡数据已聚合到同一文件

```bash
-rw-r--r-- 1 root root 10120449 Jan 30 10:34 GIL_1901644_rank_0.json
```

##### 示例二：采集指定进程 GIL 信息

通过 `pid` 参数指定目标进程，多个 PID 用逗号分隔

**采集指令：**

```bash
./sysTrace_cli enable GIL duration=10 pid=1907448,213123
```

### CacheMiss

#### 数据格式

采集硬件缓存未命中率和内存访问效率数据。

**数据格式：** 文本

#### 使用示例

**前置条件：** 需安装 `perf` 工具

**采集指令：**

```bash
./sysTrace_cli enable CacheMiss args="-e branch-misses,cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,L1-icache-load-misses,L1-icache-loads,LLC-load-misses,LLC-loads,dTLB-load-misses,dTLB-loads,iTLB-load-misses,iTLB-loads,context-switches,r6013,r6014,r7004,r7005,r7006,r7007,r5023,r102e,r102f,r27,r16,r60d6,r007c,r0008,r0011 --timeout 5000"
```

**参数说明：**

| 参数        | 必填 | 说明                       |
| :---------- | :--- | :------------------------- |
| `-e`        | 是   | 指定采集事件               |
| `--timeout` | 是   | 指定采集时长（单位：毫秒） |
| `-p`        | 否   | 指定进程 PID               |

**采集结果：**

保存位置：`/home/sysTrace/CacheMiss`

**数据格式：** 文本

```bash
-rw-r--r-- 1 root root 2885 Jan 30 11:02 CacheMiss_1935088_rank_0.txt
```

### Mutex

#### 数据格式

采集 Pthread 同步延迟数据，包括互斥锁/读写锁/自旋锁/信号量等。

**数据格式：** json

**支持的采集事件：**

| 函数名                     | 说明                   |
| :------------------------- | :--------------------- |
| pthread_mutex_lock         | 互斥锁加锁（阻塞）     |
| pthread_mutex_timedlock    | 互斥锁加锁（带超时）   |
| pthread_mutex_trylock      | 互斥锁加锁（非阻塞）   |
| pthread_rwlock_rdlock      | 读写锁读锁（阻塞）     |
| pthread_rwlock_wrlock      | 读写锁写锁（阻塞）     |
| pthread_rwlock_timedrdlock | 读写锁读锁（带超时）   |
| pthread_rwlock_timedwrlock | 读写锁写锁（带超时）   |
| pthread_rwlock_tryrdlock   | 读写锁读锁（非阻塞）   |
| pthread_rwlock_trywrlock   | 读写锁写锁（非阻塞）   |
| pthread_spin_lock          | 自旋锁加锁（阻塞）     |
| pthread_spin_trylock       | 自旋锁加锁（非阻塞）   |
| pthread_timedjoin_np       | 线程等待加入（带超时） |
| pthread_tryjoin_np         | 线程等待加入（非阻塞） |
| pthread_yield              | 线程让出 CPU           |
| sem_timedwait              | 信号量等待（带超时）   |
| sem_trywait                | 信号量等待（非阻塞）   |
| sem_wait                   | 信号量等待（阻塞）     |

#### 使用示例

##### 示例一：采集 AI 主进程 Mutex 信息

默认采集运行在 NPU 卡上的主进程（可通过 `npu-smi info` 查看）

**采集指令：**

```bash
./sysTrace_cli enable Mutex duration=10
```

**采集结果：**

保存位置：`/home/sysTrace/Mutex`

> **注意：** 多卡数据已聚合到同一文件

```bash
-rw-r--r-- 1 root root 872775 Jan 30 10:48 Mutex_1901644_rank_0.json
```

##### 示例二：采集指定进程 Mutex 信息

通过 `pid` 参数指定目标进程，多个 PID 用逗号分隔

**采集指令：**

```bash
./sysTrace_cli enable Mutex duration=10 pid=1907448,231233
```

### Ftrace

#### 数据格式

采集 Linux 内核 Ftrace 数据，包括事件、函数图和调度跟踪。

**数据格式：** 文本

#### 使用示例

**采集指令：**

```bash
./sysTrace_cli enable Ftrace duration=10 events="syscalls/sys_enter_futex,syscalls/sys_exit_futex" cpu_list=0-15
```

**参数说明：**

| 参数                | 必填 | 说明                                                         |
| :------------------ | :--- | :----------------------------------------------------------- |
| `cpu_list`          | 是   | 指定采集的 CPU 范围，支持 `0-3,5` 格式                       |
| `events`            | 否   | 指定采集事件                                                 |
| `func`              | 否   | 指定采集函数名                                               |
| `set_event_pid`     | 否   | 采集指定 PID 的 trace event 事件（对 function trace 等不生效） |
| `set_ftrace_pid`    | 否   | 采集指定 PID 的所有 ftrace 事件                              |
| `buffer_size_kb`    | 否   | 指定 ftrace 的缓存大小，默认 32768                           |
| `event_stack_trace` | 否   | 是否开启事件栈，true 开启 false 关闭，默认关闭               |
| `func_stack_trace`  | 否   | 是否开启函数栈，true 开启 false 关闭，默认关闭               |
| `function_tracer`   | 否   | 指定函数追踪模式                                             |

**采集结果：**

保存位置：`/home/sysTrace/Ftrace`

```bash
-rw-r--r-- 1 root root 870 Jan 31 16:56 Ftrace_3249973_rank_0.log
```

### Trace

#### 数据格式

采集 trace-cmd 命令行接口数据，用于 Linux 内核 Ftrace 子系统。

**数据格式：** 二进制或文本

#### 使用示例

**前置条件：** 需安装 `trace-cmd` 工具

**采集指令：**

`args` 参数为 `trace-cmd` 的参数

```bash
./sysTrace_cli enable Trace args="record -e sched sleep 5"
```

**采集结果：**

保存位置：`/home/sysTrace/Trace`

```bash
-rw-r--r-- 1 root root 665362432 Feb  3 14:45 trace.dat
```
