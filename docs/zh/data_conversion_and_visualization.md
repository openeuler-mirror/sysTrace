# 数据转换与可视化

sysTrace 支持 pb 和 json 格式落盘。**只有 pb 格式数据需要安装 protobuf 并拷贝 sysTrace_pb2.py**，json 格式数据可直接使用。

## 前置准备（仅 pb 格式）

**1. 拷贝 sysTrace_pb2.py 到 convert 目录下**

```bash
cp <path-to-sysTrace>/systrace/protos/systrace_pb2.py <path-to-sysTrace>/systrace/convert
```

**2. 安装转换脚本依赖包（仅 pb 格式需要）**

> **注意：** 以下版本号非强要求，仅需要保证 protobuf 和 protobuf-compiler 保持一致即可，可通过 `protoc --version` 确认

```bash
pip install protobuf==3.20.3
```

## 数据转换

### 转换内存 OOM 数据（pb/json）

**转换命令：**

```bash
python <path-to-sysTrace>/systrace/convert/convert_mem_to_flamegraph.py --input <path-to-hbm_trace_xxx_rank0.pb> --output <output_file>
```

转换后的数据可用于生成火焰图进行内存分析。

### 转换 torch_npu 数据（pb/json）

**转换命令：**

```bash
python <path-to-sysTrace>/systrace/convert/convert_pytorch_to_timeline.py --input <input_file> --output <output_file>
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 转换通信算子数据（CSV 格式）

**转换命令：**

```bash
python <path-to-sysTrace>/systrace/convert/convert_mspti_timeline.py --input <input_file> --output <output_file>
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 转换 offcpu/oncpu 事件（pb/json）

**转换命令：**

```bash
python <path-to-sysTrace>/systrace/convert/convert_osprobe_to_timeline.py --input <input_file> --output <output_file>
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 转换 IO 数据（pb/json）

**转换命令：**

```bash
python <path-to-sysTrace>/systrace/convert/convert_io_to_timeline.py --input <input_file> --output <output_file>
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 转换 GIL 数据（JSON）

**转换命令：**

```bash
python systrace/convert/convert_gil.py --input <input_file> --output <output.json>
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 转换 Ftrace 数据（文本）

以下事件类型支持转换为 JSON 格式（注意：不支持开启栈）

#### sched 事件

**系统软中断跟踪**

```bash
./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="irq/softirq_entry,irq/softirq_exit,irq/softirq_raise"
```

**系统硬中断跟踪**

```bash
./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="irq/irq_handler_entry,irq/irq_handler_exit"
```

**任务调度跟踪**

```bash
./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="sched/sched_switch,sched/sched_wakeup,sched/sched_waking,sched/sched_migrate_task,sched/sched_wakeup_new"
```

**转换脚本使用：**

```bash
python systrace/convert/convert_ftrace.py --input <input_file> --output <output.json> --type sched
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

#### mmap_lock 事件

**采集指令：**

```bash
./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="mmap_lock/mmap_lock_start_locking,mmap_lock/mmap_lock_acquire_returned,mmap_lock/mmap_lock_released"
```

**转换脚本使用：**

```bash
python systrace/convert/convert_ftrace.py --input <input_file> --output <output.json> --type mmaplock
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 采集结果汇总

**功能说明：** 将多个 JSON 格式的采集结果汇总到一个文件中，便于统一展示

**脚本位置：** `systrace/convert/trace_aggregator.py`

**使用方式：**

```bash
python systrace/convert/trace_aggregator.py --input <input_dir> --output <output_file>
```

**参数说明：**

| 参数       | 说明               |
| :--------- | :----------------- |
| `--input`  | JSON 文件所在目录  |
| `--output` | 输出的合并文件路径 |

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

## 数据可视化

将最终的 JSON 数据上传到 [Perfetto](https://ui.perfetto.dev/) 并展示，通过 **Open trace file** 加载数据。

### CacheMiss 可视化

**数据格式：** 文本

**查看方式：** 直接查看文件内容

**示例输出：**

``` bash
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

### Mutex 可视化

**数据格式：** JSON

**可视化方式：** 可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示

### Ftrace 可视化

**数据格式：** 文本

**查看方式：** 直接查看文件内容

### Trace 可视化

**数据格式：** 二进制或文本

**查看方式：** 直接查看文件内容
