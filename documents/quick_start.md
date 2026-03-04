# 1. 认识sysTrace

## 1.1 简介

sysTrace 是一款应用于 AI 训练任务的性能监控与故障诊断工具。在 AI 训练过程中，训练任务故障会导致训练成本浪费，主要业务痛点如下：

- AI 训练性能故障缺乏常态化监控、检测能力
- Host bound 引发的 AI 任务慢、卡故障缺乏全栈跟踪能力

 sysTrace 支持以下功能：

- 采集 torch_npu 层的 Python 函数调用栈
- 采集 CANN 层的内存持有情况，判断是否发生 HBM OOM 故障
- 采集 MSPTI 的通信算子下发/执行，判断是否发生算子慢的情况，从而定位到慢卡
- 采集 oncpu/offcpu 事件，判断 AI 训练中是否存在其他进程抢占 CPU 导致训练慢的问题

sysTrace 使用流程依次是：数据采集、数据落盘、数据分析、数据转换与可视化

# 2. 安装 sysTrace

## 2.1 硬软件要求

**操作系统：** openEuler -- 内核版本 5.10.0 +

**软件版本：**

- CANN 8.0RC3
- torch 2.1.0
- torch_npu 2.1.0.post10

## 2.2 安装 sysTrace

### 2.2.1 下载源码

```bash
git clone https://gitcode.com/openeuler/sysTrace.git
```

### 2.2.2 安装依赖包

#### 2.2.2.1 openEuler 系统

```bash
## 软件包版本要求：libbpf >= 0.8.1, clang >= 10.0.0, gcc >= 8.3.0, bpftool >= 6.8.0 libunwind >=1.7
## 如果版本均满足则跳过下面的安装依赖步骤
yum install gcc g++ cmake make python3-devel protobuf-compiler protobuf-devel protobuf-c-devel libbpf clang libbpf-devel bpftool elfutils-devel elfutils-libelf-devel nlohmann-json-devel libunwind libunwind-devel
```

#### 2.2.2.2 Ubuntu 系统

```bash
apt install gcc g++ cmake make python3-dev protobuf-compiler libprotobuf-dev libprotobuf-c-dev libbpf-dev clang elfutils libelf-dev pkg-config libbpf0 libdw-dev nlohmann-json3-dev protobuf-c-compiler libunwind8 libunwind8-dev
```

### 2.2.3 安装依赖

安装 sysTrace 依赖libbpf、 bpftool。如果系统自带的libbpf、 bpftool 版本不满足要求（libbpf >= 0.8.1，bpftool >= 6.8.0），需要手动安装。

#### 2.2.3.1 安装 libbpf

```bash
git clone https://github.com/libbpf/libbpf.git
cd libbpf
git checkout v0.8.1
cd src
make && make install
```

#### 2.2.3.2 安装 bpftool

```bash
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool
git submodule update --init
cd src
make && make install
```

### 2.2.4 编译项目

sysTrace 支持两种数据格式：pb（protobuf）和 json。编译时可以选择不同的格式：

**编译为 pb 格式（默认）：**

```bash
cd sysTrace
bash build.sh
```

**编译为 json 格式：**

```bash
cd sysTrace
bash build.sh --mode=json
```

**关闭默认python采集**

```bash
cd sysTrace
bash build.sh --python-tracing=off
```

**编译产物说明：**

编译产物均在 `build` 目录下，主要用到 `libsysTrace.so`（用于LD_PRELOAD挂载） 和 `sysTrace_cli`（命令行工具）

```bash
# ll build/
total 1776
-rw-r--r--. 1 root root   17000 Jun 12 16:58 CMakeCache.txt
drwxr-xr-x. 7 root root    4096 Jun 12 17:10 CMakeFiles
-rw-r--r--. 1 root root    1798 Jun 12 16:58 cmake_install.cmake
-rw-r--r--. 1 root root  534270 Jun 12 17:10 libcommon.a
-rwxr-xr-x. 1 root root 1209296 Jun 12 17:10 libsysTrace.so
-rw-r--r--. 1 root root   20479 Jun 12 17:10 Makefile
drwxr-xr-x. 3 root root    4096 Jun 12 17:10 protos
-rwxr-xr-x. 1 root root   76736 Jun 12 17:10 sysTrace_cli
```

# 3. 数据采集

## 3.1 背景

在 AI 训练过程中，性能问题和故障诊断是关键挑战。为了实现对训练过程的全面监控和问题定位，sysTrace 需要采集多维度的性能数据。数据采集是 sysTrace 功能实现的基础，通过收集 torch_npu 层、CANN 层、MSPTI 通信算子以及系统级事件等数据，为后续的性能分析和故障诊断提供原始素材。

数据采集模块的主要作用包括：

- 实时捕获训练过程中的关键性能指标
- 记录可能导致性能问题的异常事件
- 为性能劣化检测和慢卡定位提供数据支撑
- 帮助用户深入了解训练任务的资源使用情况和执行状态

## 3.2 数据采集方式

sysTrace 通过 `LD_PRELOAD` 方式将动态库加载到 AI 训练任务中，实现对训练过程的无侵入式数据采集：

### 3.2.1 方式一：使用低版本 libunwind（< 1.7）

系统自带的低于 1.7 版本的 libunwind 存在未知错误 ，需要手动下载最新版本的 libunwind

源码安装libunwind方法：

```bash
git clone https://github.com/libunwind/libunwind.git
cd libunwind && git checkout v1.8.2
./configure --prefix=/usr/local --enable-shared --enable-static
make -j$(nproc) && make install
```

使用sysTrace：

```bash
LD_PRELOAD=/usr/local/lib/libunwind.so.8.2.0:/usr/local/lib/libunwind-aarch64.so.8.2.0:/home/ascend-toolkit-bak/ascend-toolkit/8.0.RC3.10/tools/mspti/lib64/libmspti.so:<path-to-sysTrace>/systrace/build/libsysTrace.so python ...
```

### 3.2.2 方式二：使用高版本 libunwind（>= 1.7）

如果环境中的 libunwind 版本大于等于 1.7，使用以下命令：

```bash
LD_PRELOAD=/home/ascend-toolkit-bak/ascend-toolkit/8.0.RC3.10/tools/mspti/lib64/libmspti.so:<path-to-sysTrace>/systrace/build/libsysTrace.so python ...
```

# 4. 数据落盘

## 4.1 背景

在 AI 训练性能监控与故障诊断过程中，实时采集的数据需要持久化存储，以便进行后续的离线分析、性能劣化检测和故障定位。数据落盘是 sysTrace 功能链中的关键环节，它将内存中临时存储的各类性能数据（如 torch_npu 调用栈、CANN 层内存信息、MSPTI 通信算子数据、系统级事件等）保存到磁盘，为后续的数据分析和可视化提供原始素材。

数据落盘功能的主要作用包括：

- 实现数据的持久化存储，避免训练过程中数据丢失
- 支持多卡数据的独立存储和管理
- 为离线分析和故障诊断提供完整的数据基础
- 便于在集群环境中收集和汇总多节点数据

## 4.2 存储位置与结构

所有采集的数据当前存放在 `/home/sysTrace` 目录下，每张卡上的数据以独立一个文件保存。

**目录结构：**

```bash
# ll /home/sysTrace/
drwxr-xr-x. 2 root root 4096 Jun 12 17:01 cann     # 内存数据
drwxr-xr-x. 2 root root 4096 Jun 12 17:01 mspti    # 通信算子数据
drwxr-xr-x. 2 root root 4096 Jun 12 17:01 timeline # torch_npu 层数据
drwxr-xr-x. 2 root root 4096 Jun 12 17:01 osprobe  # offcpu/oncpu 事件
```

> **注意：** 集群多节点环境，建议将保存目录 `/home/sysTrace` 映射到共享目录，否则需要手动将每台节点上的数据拷贝。

# 5. 数据分析

## 5.1 背景

在 AI 训练过程中，性能问题和故障是影响训练效率和成本的关键因素。尽管 sysTrace 能够采集多维度的性能数据，但这些原始数据本身并不能直接揭示训练过程中的问题。数据分析模块是 sysTrace 的核心智能组件，它通过先进的算法对采集到的各类数据进行深度分析，实现对训练性能的实时监控、异常检测和故障定位。

AI 训练面临的主要性能挑战包括：

- 训练过程中的性能突然劣化（FailSlow），导致训练时间显著增加
- 多卡/多节点训练环境下的性能不一致，存在"慢卡"问题
- 缺乏自动化的异常检测和根因分析能力
- 训练任务阻塞死等严重故障难以快速定位

数据分析模块的主要作用包括：

- 实时监测训练性能指标，及时发现性能劣化和异常
- 精确定位导致性能问题的具体节点、算子或系统资源
- 提供量化的性能分析结果，支持故障根因诊断
- 降低人工分析的复杂度和时间成本，提高问题解决效率

sysTrace 提供了两大核心分析算法：FailSlow 算法用于性能劣化感知，慢卡定界算法用于定位具体的性能瓶颈点。

## 5.2 FailSlow 算法

### 5.2.1 算法背景

FailSlow（性能劣化）是 AI 训练中常见的性能问题，表现为训练过程中某个或某些步骤的执行时间突然显著增加，导致整体训练效率下降。与传统的硬件故障不同，FailSlow 问题往往更加隐蔽，难以通过简单的监控指标直接发现。

FailSlow 算法是 sysTrace 针对这一痛点设计的核心算法，它通过对训练过程中每个 step 的执行时间进行实时监测和分析，能够：

- 自动识别训练过程中的性能劣化点
- 量化评估性能劣化的程度
- 区分正常的性能波动和异常的性能劣化
- 检测训练任务是否 hang 死

该算法采用滑动窗口和统计分析相结合的方式，能够适应不同训练任务的动态特性，有效避免误报和漏报。

### 5.2.2 参数配置

| 参数                        | 类型   | 说明                                                       | 默认值                                                       |
| --------------------------- | ------ | ---------------------------------------------------------- | ------------------------------------------------------------ |
| training_log                | string | 算法输入 torch 数据路径，以 "*.timeline" 结尾，取 0 卡即可 | /home/workspace/hbdir/systrace/localhost.localdomain--00000.timeline |
| fail_slow_perception_path   | string | 劣化感知算法输出结果，保存为 json 文件                     | /etc/systrace/result/fail_slow/fail_slow_perception_result_failSlow_1753099791.json |
| max_data_queue_steps        | int    | 缓存 step 数据最大队列                                     | 500                                                          |
| min_startup_detection_steps | int    | 启动检测的最小 step 数量                                   | 10                                                           |
| task_stable_step            | int    | 任务初始训练时 step 稳定的数量                             | 3                                                            |
| fail_slow_span_mins         | float  | 劣化感知算法的检测周期，单位 min                           | 30                                                           |
| hang_times_mins_thr         | float  | 判断任务是否 hang 的阈值，单位 min                         | 30                                                           |
| steps_window_size           | int    | 滑动窗口大小                                               | 5                                                            |
| k_sigma                     | int    | bboxplot 算法的 ksigma 取值                                | 3                                                            |
| anomaly_degree_thr          | float  | 检测值偏离均值的程度                                       | 0.2                                                          |

### 5.2.3 执行算法

```bash
python failslow/fail_slow_detection.py
```

### 5.2.4 输出结果

**感知结果字段表：**

| 字段                | 类型   | 说明                                 | 默认值                                                       |
| ------------------- | ------ | ------------------------------------ | ------------------------------------------------------------ |
| is_anomaly          | bool   | 检测数据是否异常                     | True                                                         |
| anomaly_count_times | int    | 检测出的异常点数                     | 1                                                            |
| anomaly_info        | list   | 记录异常信息，每个元素对应一个异常点 | {'training_step': 16, 'anomaly_time': '2025-06-12 19:39:24', 'anomaly_degree': 26.053, 'anomaly_training_time': '69435ms', 'normal_training_time': '2566.6ms'} |
| anomaly_type        | string | 检测结果类型：normal, failslow, hang | failslow                                                     |
| start_time          | int    | 检测开始时间                         | 1749728380752                                                |
| end_time            | int    | 检测结束时间                         | 1749728419305                                                |

**输出样例：**

```json
{
  "is_anomaly": true,
  "anomaly_count_times": 1,
  "anomaly_info": [{
    "training_step": 16,
    "anomaly_time": "2025-06-12 19:39:24",
    "anomaly_degree": 26.053,
    "anomaly_training_time": "69435ms",
    "normal_training_time": "2566.6ms"
  }],
  "anomaly_type": "failSlow",
  "start_time": 1749728380752,
  "end_time": 1749728419305
}
```

## 5.3 慢卡定界算法

### 5.3.1 算法背景

在多卡或多节点分布式训练环境中，"慢卡"问题是导致训练效率下降的主要原因之一。由于硬件差异、资源竞争、网络拥塞等因素，不同节点或卡的训练速度可能出现不一致，最终导致整个训练任务被最慢的卡拖慢（木桶效应）。

慢卡定界算法是 sysTrace 提供的另一核心算法，它在 FailSlow 算法检测到性能劣化的基础上，进一步定位具体的性能瓶颈：

- 识别出导致整体性能下降的具体卡或节点
- 区分是计算慢、通信慢还是存储慢导致的性能问题
- 提供详细的性能对比数据，支持根因分析
- 适应不同的分布式训练框架和通信模式

该算法通过对各节点/卡的算子执行时间、通信延迟等指标进行对比分析，能够快速定位性能瓶颈，帮助用户有针对性地优化训练配置或硬件环境。

### 5.3.2 参数配置

#### 5.3.2.1 model_config.json

`model_config.json` 文件（/etc/systrace/config目录下）是用于配置模型运行所需的参数，主要包含以下配置项：

| 配置项                        | 类型   | 说明                                                         | 默认值                                |
| ----------------------------- | ------ | ------------------------------------------------------------ | ------------------------------------- |
| with_fail_slow                | bool   | 配置启动慢节点检测性能劣化来源于性能劣化检测的时刻还是手动配置 | false                                 |
| slow_node_detection_range_times | list   | 慢节点检测输入的时间范围                                     | []                                    |
| slow_node_detection_time_span_hours | float | 慢节点检测的时间长度，单位小时                               | 0.5                                   |
| slow_node_detection_path      | string | 慢节点检测结果保存路径                                      | "/etc/systrace/result/slow_node"      |
| data_type                     | string | 算子数据的格式                                              | "json"                                |
| root_path                     | string | 算子数据的输入路径                                      | "/home/hbdir/systrace_failslow/data/baseline" |
| enable_detect_type            | dict   | 检测不同故障类型的开关                                      | 见下方说明                           |
| fail_slow_ops                 | dict   | 检测不同故障类型对应的观测点                                | 见下方说明                           |
| save_image                    | string | 时序数据保存的路径，用于 debug 算法效果                      | "image"                               |
| record_kpi                    | bool   | 时序数据是否记录到检测结果中                                | false                                 |
| use_plot                      | bool   | 时序数据保存开关，用于 debug 算法效果                      | false                                 |
| max_num_normal_results        | int    | 检测结果最大记录正常节点数据数量                            | 16                                    |
| look_back                     | int    | 告警抑制，单位分钟                                          | 20                                    |
| hccl_domain                   | dict   | 通信域默认配置，格式为字典                                  | {}                                    |
| rank_table_json               | string | rank_table 配置文件路径，用于 mindspore 通信域配置           | "./rank_table.json"                   |
| debug_data                    | bool   | debug 模式，会保存算子执行和算子下发的中间文件              | false                                 |

**enable_detect_type 配置说明：**

```json
{
  "enable_cal": true,           // 计算慢开关
  "enable_op_launch": false,     // 算子下发慢开关
  "enable_comm": false,          // 通信慢开关
  "enable_dataloader": false,    // 输入模型数据加载慢开关
  "enable_ckpt": false          // 模型保存慢开关
}
```

**fail_slow_ops 配置说明：**

```json
{
  "cal_slow": "HcclAllGather",        // 计算慢对应的观测点
  "op_launch_slow": "HcclAllGather_launch", // 算子下发慢对应的观测点
  "comm_slow": "HcclBatchSendRecv",    // 通信慢对应的观测点
  "dataloader_slow": "Dataloader",     // 输入模型数据加载慢对应的观测点
  "ckpt_slow": "SaveCkpt"              // 模型保存慢对应的观测点
}
```

#### 5.3.2.2 metric_config.json

 `metric_config.json` 文件（/etc/systrace/config目录下）是用于配置所有指标的检测算法参数，每个指标独立配置。

**支持的指标列表：**

| 指标名称                  | 指标类型 | 说明                                     | 对应故障类型       |
| ------------------------- | -------- | ---------------------------------------- | ------------------ |
| HcclAllGather            | device   | 计算慢对应的观测点                       | 计算慢             |
| HcclAllGather_launch     | host     | 算子下发慢对应的观测点                   | 算子下发慢         |
| HcclBatchSendRecv        | device   | 通信慢对应的观测点                       | 通信慢             |
| Dataloader               | host     | 输入模型数据加载慢对应的观测点           | 数据加载慢         |
| SaveCkpt                 | host     | 模型保存慢对应的观测点                   | 模型保存慢         |

**HcclAllGather 指标配置示例：**

| 配置项              | 类型   | 说明                                                         |
| ------------------- | ------ | ------------------------------------------------------------ |
| metric_type         | string | 指标类型，取值 "device" 和 "host"                           |
| aggregation        | dict   | 指标聚合配置                                                 |
| priority           | int    | 检测优先级                                                   |
| alarm_filter_window_size | int | 告警过滤窗口大小，表示检测出的异常点连续个数                |
| space_detector      | dict   | 节点间对比检测器配置，不配置为 "null"                        |
| time_detector       | dict   | 单节点时序异常检测配置，不配置为 "null"                     |

**aggregation 配置说明：**

| 配置项              | 类型   | 说明                                                         |
| ------------------- | ------ | ------------------------------------------------------------ |
| during_s            | int    | 聚合窗口大小，单位秒                                       |
| funcs              | list   | 聚合方法配置                                                 |

**funcs 配置说明：**

| 配置项       | 类型   | 说明                                                         |
| ------------ | ------ | ------------------------------------------------------------ |
| func         | string | 聚合方法，可选值："min"、"max"、"mean"、"percentile" 等         |
| func_params  | dict   | 聚合方法配置参数，根据不同的聚合方法配置                     |

**space_detector 配置说明：**

| 配置项              | 类型    | 说明                                                         |
| ------------------- | ------- | ------------------------------------------------------------ |
| dist_metric          | string  | 节点间距离函数类型，可选值："euclidean" 等                   |
| eps                  | float   | DBSCAN 聚类参数的阈值，点间距离大于该值则为另一类           |
| cv_threshold          | float   | 判断值偏离均值的程度，偏移过大则认为是异常点               |
| min_samples          | int     | DBSCAN 最小成新簇的点数                                       |
| window_size          | int     | 窗口大小，表示单次检测的窗口，不重叠                       |
| scaling              | bool    | 表示时间序列是否归一化                                      |
| type                 | string  | 空间检测器类型，可选值："SlidingWindowDBSCAN"、"OuterDataDetector" |

**time_detector 配置说明：**

| 配置项              | 类型    | 说明                                                         |
| ------------------- | ------- | ------------------------------------------------------------ |
| preprocess_eps        | float   | DBSCAN 预处理的阈值                                         |
| preprocess_min_samplesES | int     | DBSCAN 预处理的最小点数                                     |
| type                 | string  | 时间检测器类型，可选值："TSDBSCANDetector"、"SlidingWindowKSigmaDetector" |
| n_sigma_method       | dict    | 当为 "SlidingWindowKSigmaDetector" 类型时的配置                 |

**n_sigma_method 配置说明：**

| 配置项                    | 类型    | 说明                                                         |
| ------------------------- | ------- | ------------------------------------------------------------ |
| type                       | string  | SlidingWindowKSigmaDetector 采用的检测算法                     |
| training_window_size       | int     | 滑动窗口的最大值，超过该值，覆盖已有 value                             |
| min_update_window_size   | int     | 滑动窗口的最小更新值                                     |
| min_std_val               | float   | 最小标准差，当标准差为 0 时，设置为最小标准差               |
| bias                      | float   | 边界基础上的偏置系数                                     |
| abs_bias                  | float   | 边界基础上的偏置值                                       |
| nsigma_coefficient         | int     | Ksigma 的系数                                               |
| detect_type               | string  | 检测边界类型，可选值："lower_bound"、"upper_bound"、"bi_bound" |
| min_expert_lower_bound   | int/null | 下边界最小专家阈值，null 表示不设置专家阈值                  |
| max_expert_lower_bound   | int/null | 下边界最大专家阈值，null 表示不设置专家阈值                  |
| min_expert_upper_bound   | int/null | 上边界最小专家阈值，null 表示不设置专家阈值                  |
| max_expert_upper_bound   | int/null | 上边界最大专家阈值，null 表示不设置专家阈值                  |

### 5.3.3 执行算法

```bash
systrace-failslow
# 或者
python failslow/main.py
```

> **注意：** 算法执行前，需[参考文档](https://gitcode.com/openeuler/sysTrace/blob/master/failslow/docs/conf_introduction.md)配置对应的数据路径

### 5.3.4 输出结果

**慢卡定界算法输出字段表：**

| 字段           | 类型   | 说明                             |
| -------------- | ------ | -------------------------------- |
| resultCode     | int    | 结果码，200 表示正常，201 表示异常 |
| compute        | bool   | 计算导致的慢卡                   |
| network        | bool   |  通信导致的慢卡                   |
| storage        | bool   | 存储导致的慢卡                   |
| abnormalDetail | list   | 异常 rank 卡的信息               |
| normalDetail   | list   | 正常 rank 卡的信息               |
| errorMsg       | string | 记录异常信息                     |
| timestamp      | int    | 故障发生时间                     |

**输出样例：**

```json
{
  "resultCode": 201,
  "compute": true,
  "network": false,
  "storage": false,
  "abnormalDetail": [
    {
      "objectId": "3",
      "serverIp": "9.13.100.7",
      "deviceInfo": "rank_3",
      "kpiId": "HcclAllGather",
      "methodType": "SPACE",
      "kpiData": [],
      "relaIds": [0, 1, 2, 4, 5, 6, 7],
      "omittedDevices": []
    }
  ],
  "normalDetail": [
    {
      "objectId": "0",
      "serverIp": "9.13.100.7",
      "deviceInfo": "rank_0",
      "kpiId": "HcclAllGather",
      "methodType": "SPACE",
      "kpiData": [],
      "relaIds": [],
      "omittedDevices": []
    }
  ],
  "errorMsg": "",
  "timestamp": 1749084984
}
```

# 6. 数据转换与可视化

sysTrace 支持 pb 和 json 格式落盘。**只有 pb 格式数据需要安装 protobuf 并拷贝 sysTrace_pb2.py**，json 格式数据可直接使用。

## 6.1 前置准备（仅 pb 格式）

**1. 拷贝 sysTrace_pb2.py 到 convert 目录下**

```bash
cp <path-to-sysTrace>/systrace/protos/systrace_pb2.py <path-to-sysTrace>/systrace/convert
```

**2. 安装转换脚本依赖包（仅 pb 格式需要）**

> **注意：** 以下版本号非强要求，仅需要保证 protobuf 和 protobuf-compiler 保持一致即可，可通过 `protoc --version` 确认

```bash
pip install protobuf==3.20.3
```

## 6.2 数据转换

### 6.2.1 转换内存 OOM 数据（pb/json）

**转换命令：**

```bash
python <path-to-sysTrace>/systrace/convert/convert_mem_to_flamegraph.py --input <path-to-hbm_trace_xxx_rank0.pb> --output <output_file>
```

转换后的数据可用于生成火焰图进行内存分析。

### 6.2.2 转换 torch_npu 数据（pb/json）

**转换命令：**

```bash
python <path-to-sysTrace>/systrace/convert/convert_pytorch_to_timeline.py --input <input_file> --output <output_file>
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 6.2.3 转换通信算子数据（CSV 格式）

**转换命令：**

```bash
python <path-to-sysTrace>/systrace/convert/convert_mspti_timeline.py --input <input_file> --output <output_file>
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 6.2.4 转换 offcpu/oncpu 事件（pb/json）

**转换命令：**

```bash
python <path-to-sysTrace>/systrace/convert/convert_osprobe_to_timeline.py --input <input_file> --output <output_file>
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 6.2.5 转换 IO 数据（pb/json）

**转换命令：**

```bash
python <path-to-sysTrace>/systrace/convert/convert_io_to_timeline.py --input <input_file> --output <output_file>
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 6.2.6 转换 GIL 数据（JSON）

**转换命令：**

```bash
python systrace/convert/convert_gil.py --input <input_file> --output <output.json>
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 6.2.7 转换 Ftrace 数据（文本）

以下事件类型支持转换为 JSON 格式（注意：不支持开启栈）

#### 6.2.7.1 sched 事件

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

#### 6.2.7.2 mmap_lock 事件

**采集指令：**

```bash
./sysTrace_cli enable Ftrace duration=10 cpu_list=0-31 events="mmap_lock/mmap_lock_start_locking,mmap_lock/mmap_lock_acquire_returned,mmap_lock/mmap_lock_released"
```

**转换脚本使用：**

```bash
python systrace/convert/convert_ftrace.py --input <input_file> --output <output.json> --type mmaplock
```

转换后的 JSON 文件可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示。

### 6.2.8 采集结果汇总

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

## 6.3 数据可视化

将最终的 JSON 数据上传到 [Perfetto](https://ui.perfetto.dev/) 并展示，通过 **Open trace file** 加载数据。

### 6.3.1 CacheMiss 可视化

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

### 6.3.2 Mutex 可视化

**数据格式：** JSON

**可视化方式：** 可上传到 [Perfetto](https://www.ui.perfetto.dev/) 或 MindInsight 进行展示

### 6.3.3 Ftrace 可视化

**数据格式：** 文本

**查看方式：** 直接查看文件内容

### 6.3.4 Trace 可视化

**数据格式：** 二进制或文本

**查看方式：** 直接查看文件内容

# 7. 附录：高级配置与使用

## 7.1 环境配置

### 7.1.1 日志配置

#### 7.1.1.1 日志落盘位置

默认路径：`/var/log/sysTrace`

```bash
export SYSTRACE_LOG_PATH=/var/log/sysTrace
```

#### 7.1.1.2 日志级别

默认级别：`INFO`

日志级别从高到低依次为：`DEBUG`、`WARN`、`INFO`、`ERROR`、`FATAL`

```bash
export SYSTRACE_LOG_LEVEL=INFO
```

### 7.1.2 数据存储配置

#### 7.1.2.1 采集数据落盘位置

默认路径：`/home/sysTrace`

```bash
export SYSTRACE_DUMP_PATH=/home/sysTrace
```

## 7.2 命令行工具

### 7.2.1 工具说明

`sysTrace_cli` 是 sysTrace 项目自带的命令行工具，用于与训练/推理任务中的 sysTrace 服务通信，控制各采集项的启停。

**使用前提：**

- 项目编译完成后，`sysTrace_cli` 位于 `build` 目录
- 需通过 `LD_PRELOAD` 将 `libsysTrace.so` 注入到推理/训练任务中
- 推理/训练任务已正常启动

### 7.2.2 使用方式

通过 设置`LD_PRELOAD` 环境变量将 `libsysTrace.so` 动态库加载到 AI 推理/训练任务中，从而启用 sysTrace 的数据采集功能。

```bash
export LD_PRELOAD=$LD_PRELOAD:<path-to-sysTrace>/systrace/build/libsysTrace.so
```

> **注意：** 
>
> - `<path-to-sysTrace>` 需要替换为实际的 sysTrace 项目路径
> - 编译时选择的数据格式（pb/json）会影响采集数据的格式

### 7.2.3 命令格式

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

## 7.3 采集项列表

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

## 7.4 数据格式与使用示例

### 7.4.1 HBM

#### 7.4.1.1 数据格式

采集 HBM 事件数据，包括内存持有情况，用于判断是否发生 HBM OOM 故障。

**数据格式：** pb/json

#### 7.4.1.2 使用示例

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

### 7.4.2 IO

#### 7.4.2.1 数据格式

采集磁盘和网络 I/O 延迟/吞吐量数据。

**数据格式：** pb/json

#### 7.4.2.2 使用示例

**采集指令：**

```bash
./sysTrace_cli enable IO duration=10
```

**采集结果：**

保存位置：`/home/sysTrace/io_trace`

**数据格式：** pb/json

```bash
-rw-r--r-- 1 root root 42450 Jan 30 09:45 io_trace_rank0_1868164.pb
-rw-r--r-- 1 root root 12629 Jan 30 09:45 io_trace_rank1_1868165.pb
```

### 7.4.3 MSPTI

#### 7.4.3.1 数据格式

采集 NVIDIA/Atlas 活动跟踪数据，包括通信算子下发/执行信息，用于判断是否发生算子慢的情况。

**数据格式：** CSV

**数据字段：**

```python
Flag,Id,Kind,Name,SourceKind,Timestamp,msptiObjectId_Ds_DeviceId,msptiObjectId_Ds_StreamId,msptiObjectId_Pt_ProcessId,msptiObjectId_Pt_ThreadId
```

#### 7.4.3.2 使用示例

**采集指令：**

```bash
./sysTrace_cli enable MSPTI duration=10
```

**采集结果：**

保存位置：`/home/sysTrace/mspti`

**数据格式：** CSV

```bash
-rw-r--r-- 1 root root 658179 Jan 30 09:48 mspti-marker-76.53.151.141-0.csv
-rw-r--r-- 1 root root 658179 Jan 30 09:48 mspti-marker-76.53.151.141-1.csv
```

### 7.4.4 CPU

#### 7.4.4.1 数据格式

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

#### 7.4.4.2 使用示例

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

### 7.4.5 Memory

#### 7.4.5.1 数据格式

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

#### 7.4.5.2 使用示例

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

### 7.4.6 GIL

#### 7.4.6.1 数据格式

采集 Python 全局解释器锁（GIL）争用和延迟跟踪数据。

**数据格式：** json

#### 7.4.6.2 使用示例

##### 7.4.6.2.1 示例一：采集 AI 主进程 GIL 信息

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

##### 7.4.6.2.2 示例二：采集指定进程 GIL 信息

通过 `pid` 参数指定目标进程，多个 PID 用逗号分隔

**采集指令：**

```bash
./sysTrace_cli enable GIL duration=10 pid=1907448,213123
```

### 7.4.7 CacheMiss

#### 7.4.7.1 数据格式

采集硬件缓存未命中率和内存访问效率数据。

**数据格式：** 文本

#### 7.4.7.2 使用示例

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

### 7.4.8 Mutex

#### 7.4.8.1 数据格式

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

#### 7.4.8.2 使用示例

##### 7.4.8.2.1 示例一：采集 AI 主进程 Mutex 信息

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

##### 7.4.8.2.2 示例二：采集指定进程 Mutex 信息

通过 `pid` 参数指定目标进程，多个 PID 用逗号分隔

**采集指令：**

```bash
./sysTrace_cli enable Mutex duration=10 pid=1907448,231233
```

### 7.4.9 Ftrace

#### 7.4.9.1 数据格式

采集 Linux 内核 Ftrace 数据，包括事件、函数图和调度跟踪。

**数据格式：** 文本

#### 7.4.9.2 使用示例

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

### 7.4.10 Trace

#### 7.4.10.1 数据格式

采集 trace-cmd 命令行接口数据，用于 Linux 内核 Ftrace 子系统。

**数据格式：** 二进制或文本

#### 7.4.10.2 使用示例

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
