# 数据分析

## 背景

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

## FailSlow 算法

### 算法背景

FailSlow（性能劣化）是 AI 训练中常见的性能问题，表现为训练过程中某个或某些步骤的执行时间突然显著增加，导致整体训练效率下降。与传统的硬件故障不同，FailSlow 问题往往更加隐蔽，难以通过简单的监控指标直接发现。

FailSlow 算法是 sysTrace 针对这一痛点设计的核心算法，它通过对训练过程中每个 step 的执行时间进行实时监测和分析，能够：

- 自动识别训练过程中的性能劣化点
- 量化评估性能劣化的程度
- 区分正常的性能波动和异常的性能劣化
- 检测训练任务是否 hang 死

该算法采用滑动窗口和统计分析相结合的方式，能够适应不同训练任务的动态特性，有效避免误报和漏报。

### 参数配置

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

### 执行算法

```bash
python failslow/fail_slow_detection.py
```

### 输出结果

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

## 慢卡定界算法

### 算法背景

在多卡或多节点分布式训练环境中，"慢卡"问题是导致训练效率下降的主要原因之一。由于硬件差异、资源竞争、网络拥塞等因素，不同节点或卡的训练速度可能出现不一致，最终导致整个训练任务被最慢的卡拖慢（木桶效应）。

慢卡定界算法是 sysTrace 提供的另一核心算法，它在 FailSlow 算法检测到性能劣化的基础上，进一步定位具体的性能瓶颈：

- 识别出导致整体性能下降的具体卡或节点
- 区分是计算慢、通信慢还是存储慢导致的性能问题
- 提供详细的性能对比数据，支持根因分析
- 适应不同的分布式训练框架和通信模式

该算法通过对各节点/卡的算子执行时间、通信延迟等指标进行对比分析，能够快速定位性能瓶颈，帮助用户有针对性地优化训练配置或硬件环境。

### 参数配置

#### model_config.json

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

#### metric_config.json

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

### 执行算法

```bash
systrace-failslow
# 或者
python failslow/main.py
```

> **注意：** 算法执行前，需[参考文档](https://gitcode.com/openeuler/sysTrace/blob/master/failslow/docs/conf_introduction.md)配置对应的数据路径

### 输出结果

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
