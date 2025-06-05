# 配置文件介绍

systrace-failslow运行的参数，主要通过**model_config.json**和**metic_config.json**配置，其中前者配置代码运行相关的参数，后者配置算法配置相关的参数。


全部配置文件归档在[config](https://gitee.com/openeuler/sysTrace/tree/master/config)目录。


## 配置文件目录结构

启动配置文件目录结构如下，主要分为两类：`启动参数配置`和`日志参数配置`。

```
systrace-failslow               # systrace-failslow 主目录
└─ config                   # 配置文件目录
   ├─ model_config.json    # 模型参数配置
   ├─ metric_config.json      # 算法参数配置
```

## 模型参数配置

在文件model_config.json中，配置模型运行所需的参数。该配置项中，主要包含：

- with_fail_slow: 配置启动慢节点检测性能劣化来源于性能劣化检测的时刻还是手动配置, 默认为false



- task_stable_step: 训练任务稳定训练的step索引，默认值为3
- min_startup_detection_steps：最小开始性能劣化检测的索引，默认值为3
- fail_slow_span_mins：性能劣化检测间隔，默认10分钟
- training_log：性能劣化输入路径，一般是训练的日志，默认为“/etc/systrace/data/rank0_mindformer.log”；
- step_data_path: 日志中解析step时延保存的路径，默认为"/etc/systrace/data/step_data.csv"；
- steps_window_size：性能劣化检测的窗口大小，默认为5；
- k_sigma：性能劣化检测算法k-sigma的阈值，默认为2；
- anomaly_degree_thr：性能劣化异常程度，表示偏离均值的绝对值程度，默认为0.2
- slow_node_detection_range_times：慢节点检测输入的时间范围，默认为空列表
- slow_node_detection_time_span_hours：慢节点检测的时间长度，默认为0.5小时
- slow_node_detection_path：慢节点检测结果保存路径，默认为"/etc/systrace/result/slow_node"
- data_type：算子数据的格式，默认为”json“
- root_path: 算子数据的输入路径，默认为”/home/hbdir/systrace_failslow/data/baseline“
- enable_detect_type：检测不同故障类型的开关，字典格式
  - enable_cal: 计算慢开关，默认为true
  - enable_op_launch: 算子下发慢开关，默认为false
  - enable_op_launch: Kafka对应的`server port`，如："9092"；
  - enable_comm: 通信慢开关，默认为false
  - enable_dataloader: 输入模型数据加载慢开关，默认为false
  - enable_ckpt: 模型保存慢开关，默认为false
- fail_slow_ops: 检测不同故障类型对应的观测点，字典格式
- cal_slow：计算慢对应的观测点，默认为"HcclAllGather"
  - op_launch_slow：算子下发慢对应的观测点，默认为“HcclAllGather_launch”
- comm_slow：通信慢对应的观测点，默认为“HcclBatchSendRecv”
  - dataloader_slow：输入模型数据加载慢对应的观测点，默认为“Dataloader”
- ckpt_slow: 模型保存满对应的观测点，默认为“SaveCkpt”


- save_image：时序数据保存的路径，用于debug算法效果，默认为“image”
- record_kpi: 时序数据是否记录到检测结果中，默认为false
- use_plot: 时序数据保存开关，用于debug算法效果，默认为false
- max_num_normal_results：检测结果最大记录正常节点数据数量，默认为16
- look_back：告警抑制，默认为20min
- hccl_domain: 通信域默认配置，格式为字典，默认为{}，实际配置示例{"tp":[[0,1,2,3], [4,5,6,7]], "dp":[[0,4], [1,5],[2,6],[3,7]]}
- rank_table_json: rank_table配置文件路径，用于mindspore通信域配置，默认路径"./rank_table.json"
- debug_data：denug模式，会保存算子执行和算子下发的中间文件，默认为false


## 算法参数配置

在文件metric_config.json中，配置所有指标的检测算法参数，每个指标独立配置。该配置项中以**HcclAllGather**指标配置举例，主要包含：


- metric_type：指标类型，string类型，取值“device”和“host”，
- aggregation：指标聚合配置，字典
  - during_s：聚合窗口大小, int类型，默认5s
  - funcs：聚合方法配置，list类型，包含元素为dict类型
    - func: 聚合方法，string类型，有“min”,"max","mean","percentile"等
    - func_params: 聚合方法配置参数，字典类型，根据不同的聚合方法配置，默认为空

- priority：指标类型，string类型，取值“device”和“host”，
- aggregation：检测优先级，int类型
- alarm_filter_window_size：告警过滤窗口大小，表示检测出的异常点连续个数，int类型，默认值为5
- space_detector: 节点间对比检测器配置，不配置为“null”
  - dist_metric: 节点间距离函数类型，“euclidean”, string类型
  - eps：Dbscan聚类参数的阈值，点间距离大于该值则为另一类， float类型
  - cv_threshold：判断值偏离均值的程度，偏移过大则认为是异常点，float类型
  - min_samples：dbscan最小成新簇的点数, int类型
  - window_size：窗口大小，表示单次检测的窗口，不重叠，int类型
  - scaling：表示时间序列是否归一化， bool类型
  - type：空间检测器类型，string类型，取值“SlidingWindowDBSCAN”，“OuterDataDetector”
- time_detector:单节点时序异常检测配置, 不配置为“null”
  - preprocess_eps: Dbscann预处理的阈值, float类型
  - preprocess_min_samples：Dbscan预处理的最小点数，int类型
  - type：时间检测器类型，string类型，取值为“TSDBSCANDetector”，“SlidingWindowKSigmaDetector”
  - n_sigma_method：当为“SlidingWindowKSigmaDetector”类型时，配置字段，dict类型
    - type：SlidingWindowKSigmaDetector采用的检测算法，可替换扩展，string类型，默认为”SlidingWindowNSigma“
    - training_window_size：滑动窗口的最大值，超过该值，覆盖已有value，int类型
    - min_update_window_size：滑动窗口的最小更新值，int类型
    - min_std_val：最小标准差，当标准差为0时，设置为最小标准差，float类型
    -  bias：边界基础上的偏置系数，float类型
    - abs_bias：边界基础上的偏置值，float类型
    - nsigma_coefficient：Ksigam的系数，int类型
    - detect_type：检测边界类型，string类型，取值为“lower_bound”,“upper_bound”,“bi_bound”
    - min_expert_lower_bound：下边界最小专家阈值，null表示不设置专家阈值，int或者null类型
    - max_expert_lower_bound：下边界最大专家阈值，null表示不设置专家阈值，int或者null类型
    - min_expert_upper_bound：上边界最小专家阈值，null表示不设置专家阈值，int或者null类型
    - max_expert_upper_bound：上边界最大专家阈值，null表示不设置专家阈值，int或者null类型

