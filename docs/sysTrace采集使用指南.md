# sysTrace采集使用指南

## 1. 前置条件

参考[部署指南](./0.quickstart.md)安装部署sysTrace。

## 2. 使用方法

### 2.1 配置项

#### 2.1.1 设置日志落盘位置，默认 /var/log/sysTrace

```bash
export SYSTRACE_LOG_PATH=/var/log/sysTrace
```

#### 2.1.2 设置日志级别，默认 INFO

日志级别从高到低依次为：

- DEBUG
- WARN
- INFO
- ERROR
- FATAL

```bash
export SYSTRACE_LOG_LEVEL=INFO
```

#### 2.1.3 设置采集数据落盘位置，默认 /home/sysTrace

```bash
export SYSTRACE_DUMP_PATH=/home/sysTrace
```

### 2.2 命令行工具sysTrace_cli

#### 2.2.1 sysTrace_cli

sysTrace_cli是sysTrace项目自带的命令行工具，用于和训练/推理任务中的sysTrace服务通讯，开启各个采集项。

项目编译完成后，sysTrace_cli在build目录中。sysTrace_cli使用前提：通过LD_PRELOAD 把libsysTrace.so注入到推理/训练任务中。推理/训练任务正常启动。

#### 2.2.2 sysTrace_cli 使用方式

```bash
./build/sysTrace_cli -h   #显示帮助文档
```

输出信息：

```
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
  sysTrace_cli enable Mutex duration=10
  sysTrace_cli enable CacheMiss args=" -e branch-misses,cache-misses,cache-references --timeout 5000"
  sysTrace_cli disable CPU
  sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="syscalls/sys_enter_futex,syscalls/sys_exit_futex"
=========================================================
```

## 3. 采集项列表

| Plugin   | 适用场景 | 命令示例 |
| :------- | :------- | :------- |
| HBM      | HBM事件 | `./sysTrace_cli enable HBM duration=10` |
| IO       | 磁盘和网络I/O延迟/吞吐量 | `./sysTrace_cli enable IO duration=10` |
| MSPTI    | NVIDIA/Atlas活动跟踪（HCCL，内核） | `./sysTrace_cli enable MSPTI duration=10` |
| CPU      | CPU利用率和上下文切换跟踪 | `./sysTrace_cli enable CPU duration=10` |
| Memory   | 内存分配和泄漏检测 | `./sysTrace_cli enable Memory duration=10` |
| GIL      | Python全局解释器锁（GIL）争用和延迟跟踪 | `./sysTrace_cli enable GIL duration=10` |
| CacheMiss | 硬件缓存未命中率和内存访问效率 | `./sysTrace_cli enable CacheMiss args="-p 27638 -e branch-misses,cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,L1-icache-load-misses,L1-icache-loads --timeout 20000"` |
| Mutex    | Pthread同步延迟（互斥锁/读写锁/自旋锁/信号量） | `./sysTrace_cli enable Mutex duration=10` |
| Ftrace   | Linux内核Ftrace（事件、函数图和调度跟踪） | `./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="raw_syscalls/sys_enter,raw_syscalls/sys_exit"` |
| Trace    | trace-cmd命令行接口，用于Linux内核Ftrace子系统 | `./sysTrace_cli enable Trace args="record -e sched sleep 5"` |

## 4. 使用示例

### 4.1 HBM

采集指令：

```bash
./sysTrace_cli enable HBM duration=10    #duration 为采集的时长，单位秒
```

指令发送成功，一张卡一条sock记录：

```
[ACK] /tmp/sysTrace_1868164.sock: SUCCESS
[ACK] /tmp/sysTrace_1868165.sock: SUCCESS
```

采集结果（默认保存位置： /home/sysTrace/hbm_trace）：

```bash
-rw-r--r-- 1 root root 30900 Jan 30 09:40 hbm_trace_rank0_1868164.pb
-rw-r--r-- 1 root root 30684 Jan 30 09:40 hbm_trace_rank1_1868165.pb
```

### 4.2 IO

采集指令：

```bash
./sysTrace_cli enable IO duration=10
```

采集结果（默认保存位置：/home/sysTrace/io_trace）：

```bash
-rw-r--r-- 1 root root 42450 Jan 30 09:45 io_trace_rank0_1868164.pb
-rw-r--r-- 1 root root 12629 Jan 30 09:45 io_trace_rank1_1868165.pb
```

### 4.3 MSPTI

采集指令：

```bash
./sysTrace_cli enable MSPTI duration=10
```

采集结果（默认保存位置：/home/sysTrace/mspti）：

```bash
-rw-r--r-- 1 root root 658179 Jan 30 09:48 mspti-marker-76.53.151.141-0.csv
-rw-r--r-- 1 root root 658179 Jan 30 09:48 mspti-marker-76.53.151.141-1.csv
```

### 4.4 CPU

采集指令：

```bash
./sysTrace_cli enable CPU duration=10
```

采集结果（CPU采集结果落盘和Memory为同一个文件，默认保存位置：/home/sysTrace/osprobe）：

```bash
-rw-r--r-- 1 root root 128010 Jan 30 09:51 os_trace_20260130_09_rank_0_1868164.pb
-rw-r--r-- 1 root root 133567 Jan 30 09:51 os_trace_20260130_09_rank_1_1868165.pb
```

### 4.5 Memory

采集指令：

```bash
./sysTrace_cli enable Memory duration=10
```

采集结果（Memory采集结果落盘和CPU为同一个文件，默认保存位置：/home/sysTrace/osprobe）：

```bash
-rw-r--r-- 1 root root 128010 Jan 30 09:51 os_trace_20260130_09_rank_0_1868164.pb
-rw-r--r-- 1 root root 133567 Jan 30 09:51 os_trace_20260130_09_rank_1_1868165.pb
```

### 4.6 GIL

#### 示例一：默认采集AI主进程（运行在NPU卡上的主进程 npu-smi info）GIL信息

采集指令：

```bash
./sysTrace_cli enable GIL duration=10
```

采集结果（GIL多卡数据已聚合到同一文件，默认保存位置：/home/sysTrace/GIL）：

```bash
-rw-r--r-- 1 root root 10120449 Jan 30 10:34 GIL_1901644_rank_0.json
```

#### 示例二：通过pid参数同时采集指定pid GIL信息（多个pid用,分隔）

采集指令：

```bash
./sysTrace_cli enable GIL duration=10 pid=1907448,213123
```

### 4.7 CacheMiss

前提：需要安装perf工具。

采集指令：

```bash
./sysTrace_cli enable CacheMiss args=" -e branch-misses,cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,L1-icache-load-misses,L1-icache-loads,LLC-load-misses,LLC-loads,dTLB-load-misses,dTLB-loads,iTLB-load-misses,iTLB-loads,context-switches,r6013,r6014,r7004,r7005,r7006,r7007,r5023,r102e,r102f,r27,r16,r60d6,r007c,r0008,r0011 --timeout 5000"
```

参数说明：

- `args` 参数中 `-e` 必选，用于指定采集事件
- `--timeout` 必选，用于指定采集时长（单位：毫秒）
- `-p` 可选，用于指定pid

采集结果（默认保存位置：/home/sysTrace/CacheMiss）：

```bash
-rw-r--r-- 1 root root 2885 Jan 30 11:02 CacheMiss_1935088_rank_0.txt
```

### 4.8 Mutex

#### 采集事件列表

| 函数名 | 说明 |
| :------- | :------- |
| pthread_mutex_lock | 互斥锁加锁（阻塞） |
| pthread_mutex_timedlock | 互斥锁加锁（带超时） |
| pthread_mutex_trylock | 互斥锁加锁（非阻塞） |
| pthread_rwlock_rdlock | 读写锁读锁（阻塞） |
| pthread_rwlock_wrlock | 读写锁写锁（阻塞） |
| pthread_rwlock_timedrdlock | 读写锁读锁（带超时） |
| pthread_rwlock_timedwrlock | 读写锁写锁（带超时） |
| pthread_rwlock_tryrdlock | 读写锁读锁（非阻塞） |
| pthread_rwlock_trywrlock | 读写锁写锁（非阻塞） |
| pthread_spin_lock | 自旋锁加锁（阻塞） |
| pthread_spin_trylock | 自旋锁加锁（非阻塞） |
| pthread_timedjoin_np | 线程等待加入（带超时） |
| pthread_tryjoin_np | 线程等待加入（非阻塞） |
| pthread_yield | 线程让出CPU |
| sem_timedwait | 信号量等待（带超时） |
| sem_trywait | 信号量等待（非阻塞） |
| sem_wait | 信号量等待（阻塞） |

#### 示例一：默认采集AI主进程（运行在NPU卡上的主进程 npu-smi info）Mutex信息

采集指令：

```bash
./sysTrace_cli enable Mutex duration=10
```

采集结果（Mutex多卡数据已聚合到同一文件，默认保存位置：/home/sysTrace/Mutex）：

```bash
-rw-r--r-- 1 root root 872775 Jan 30 10:48 Mutex_1901644_rank_0.json
```

#### 示例二：通过pid参数同时采集指定pid Mutex信息（多个pid用,分隔）

采集指令：

```bash
./sysTrace_cli enable Mutex duration=10 pid=1907448,231233
```

采集结果（Mutex多卡数据已聚合到同一文件）：

```bash
-rw-r--r-- 1 root root 729376 Jan 30 10:53 Mutex_1901644_rank_0.json
```

### 4.9 Ftrace

采集指令：

```bash
./sysTrace_cli enable Ftrace duration=10 events="syscalls/sys_enter_futex,syscalls/sys_exit_futex" cpu_list=0-15 <set_event_pid=1234>
```

参数说明：

- `cpu_list` 必选，用于指定采集的cpu范围，支持0-3,5格式
- `events` 用于指定采集事件
- `func` 用于指定采集函数名
- `set_event_pid` 可选，用于采集指定PID的trace event事件（对function trace等不生效）
- `set_ftrace_pid` 可选，用于采集指定PID的所有ftrace事件
- `buffer_size_kb` 可选，用于指定ftrace的缓存大小，默认32768
- `event_stack_trace` 可选，用于指定是否开启事件栈，true开启 false关闭，默认关闭
- `func_stack_trace` 可选，用于指定是否开启函数栈，true开启 false关闭，默认关闭
- `function_tracer` 可选，用于指定函数追踪模式

采集结果（默认保存位置：/home/sysTrace/Ftrace）：

```bash
-rw-r--r-- 1 root root 870 Jan 31 16:56 Ftrace_3249973_rank_0.log
```

### 4.10 Trace

前提：需要安装trace-cmd工具。

采集指令（args参数为 trace-cmd 参数）：

```bash
./sysTrace_cli enable Trace args="record -e sched sleep 5"
```

采集结果（默认保存位置：/home/sysTrace/Trace）：

```bash
-rw-r--r-- 1 root root 665362432 Feb  3 14:45 trace.dat
```

## 5 结果转换可视化

### 5.1 GIL

采集结果为json，可上传到 https://www.ui.perfetto.dev/ 或者MindInsight进行展示。

### 5.2 CacheMiss

采集结果为文本，可直接查看：

```
# started on Fri Jan 30 11:02:12 2026


 Performance counter stats for 'system wide':

         148649047      branch-misses                                                 (46.29%)
         195212952      cache-misses              #    0.857 % of all cache refs      (46.34%)
       22788535562      cache-references                                              (46.37%)
         196172754      L1-dcache-load-misses     #    0.85% of all L1-dcache accesses  (46.41%)
       23176613281      L1-dcache-loads                                               (46.44%)
         368753847      L1-icache-load-misses     #    2.11% of all L1-icache accesses  (46.46%)
       17451707150      L1-icache-loads                                               (46.48%)
         138700751      LLC-load-misses           #   43.21% of all LL-cache accesses  (46.50%)
         321000567      LLC-loads                                                     (46.51%)
         163158545      dTLB-load-misses          #    0.60% of all dTLB cache accesses  (46.53%)
       27021471325      dTLB-loads                                                    (46.55%)
          71692354      iTLB-load-misses          #    0.41% of all iTLB cache accesses  (46.57%)
       17324837727      iTLB-loads                                                    (43.01%)
            535323      context-switches
         631181416      r6013                                                         (42.97%)
          63274468      r6014                                                         (42.93%)
       23130888827      r7004                                                         (42.90%)
         796116934      r7005                                                         (42.87%)
       10139211440      r7006                                                         (42.84%)
        9701271710      r7007                                                         (42.83%)
        2285448540      r5023                                                         (42.81%)
        1026604354      r102e                                                         (42.80%)
         151411659      r102f                                                         (42.79%)
         328150439      r27                                                           (42.78%)
        1521606094      r16                                                           (42.78%)
         413642923      r60d6                                                         (42.77%)
          16126045      r007c                                                         (42.75%)
       61314085780      r0008                                                         (42.73%)
       69243999676      r0011                                                         (46.28%)
```

### 5.3 Mutex

采集结果为json，可上传到 https://www.ui.perfetto.dev/ 或者MindInsight进行展示。

### 5.4 Ftrace

采集结果为文本，可自行查看。以下为提供了采集结果转换脚本的事件，注意不支持开启栈。

#### 5.4.1 sched

1. 系统软中断跟踪（仅启用软中断事件）

```bash
./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="irq/softirq_entry,irq/softirq_exit,irq/softirq_raise"
```

2. 系统硬中断跟踪（仅启用硬中断事件）

```bash
./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="irq/irq_handler_entry,irq/irq_handler_exit"
```

3. 任务调度跟踪（仅调度相关事件）

```bash
./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="sched/sched_switch,sched/sched_wakeup,sched/sched_waking,sched/sched_migrate_task,sched/sched_wakeup_new"
```

可以使用 **systrace/convert** 目录下的 **convert_ftrace.py** 转换脚本转换成json格式，可上传到 https://www.ui.perfetto.dev/ 或者MindInsight进行展示。

转换脚本使用方式：

```bash
python convert_ftrace.py --input <Ftrace_3249973_rank_0.log> --output <output.json> --type <sched>
```

#### 5.4.2 mmap_lock

内核mmap_lock事件

~~~bash
./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="mmap_lock/mmap_lock_start_locking,mmap_lock/mmap_lock_acquire_returned,mmap_lock/mmap_lock_released"
~~~

转换脚本使用方式：

~~~bash
python convert_ftrace.py --input <Ftrace_3249973_rank_0.log> --output <output.json> --type <mmaplock>
~~~

### 5.5 Trace

采集结果为二进制或文本，可自行查看。

### 5.6 采集结果汇总展示

采集项结果（包括转换后）为json格式的，可以使用转换脚本（systrace/convert/trace_aggregator.py）汇总到一个文件进行展示。

展示脚本使用方式：

```bash
python trace_aggregator.py --input <json_dir> --output <merged.json>
```

merged.json 可上传到 https://www.ui.perfetto.dev/ 或者MindInsight进行展示。
