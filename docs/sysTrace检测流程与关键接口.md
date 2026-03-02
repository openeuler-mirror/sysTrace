# sysTrace 检测模式流程与关键接口解析

## 1. 两种检测模式概览

systrace-failslow 支持两种检测模式：**离线检测模式（Offline）** 和 **在线检测模式（Online）**。两种模式共享核心检测管道 `DetectionPipeline`，但数据入口、处理时序和适用场景不同。

| 维度 | 离线模式 (Offline) | 在线模式 (Online) |
|------|-------------------|-------------------|
| **入口类** | `Application` | `Task` |
| **数据来源** | `IDataSource` (配置文件指定) | 外部调用 `on_recv_all_step()` |
| **数据时序** | 一次性读取全部数据 | 流式、逐步到达 |
| **处理方式** | 同步批量处理 | 异步队列 + 后台线程 |
| **数据落盘** | 不支持 | 支持 (`IDataSink`) |
| **入口脚本** | `main.py` | `online_detection.py` |
| **适用场景** | 历史数据回溯分析 | 实时监控 |

---

## 2. 离线检测模式流程

### 2.1 启动流程

```
main.py --config config.json
    │
    ├─ 1. 创建 ComponentFactory 实例（6类：source/preprocessor/detector/reporter/extractor/sink）
    ├─ 2. ConfigLoader.load_from_file() → 解析 JSON → Pydantic 验证 → 组件实例化
    ├─ 3. Application(config).start()
    │      │
    │      ├─ 检查 task_config.data_source 是否存在
    │      │   ├─ 存在 → 创建 DetectionPipeline(data_source=...) → run_offline()
    │      │   └─ 不存在 → TaskFactory.create() → 在线模式 Task
    │      │
    │      └─ pipeline.run_offline() 执行完毕后退出
    │
    └─ 4. 应用退出
```

### 2.2 run_offline() 详细流程

```python
# pipeline.py:run_offline()
def run_offline(self, task_type, task_name):
    self.data_source.connect()              # 1. 连接数据源
    
    # 2. 读取所有数据，按 step_id 分组
    steps_buffer: Dict[int, List[StepMetrics]] = {}
    for step_metrics in self.data_source.read():
        step_id = step_metrics.step
        steps_buffer.setdefault(step_id, []).append(step_metrics)
    
    # 3. 按 step_id 排序，逐 step 处理
    for step_id in sorted(steps_buffer.keys()):
        self._process_step(steps_buffer[step_id], task_type, task_name)
    
    self.data_source.disconnect()           # 4. 断开数据源
```

**关键点：**
- 离线模式将所有数据读入内存，按 `step_id` 分组
- `_process_step()` 是核心处理方法，两种模式共用
- 离线模式不进行数据落盘（`data_sink` 为 None）
- `LocalCsvDataSource.read()` 返回迭代器，每个 `StepMetrics` 包含 1 个 `KernelType`

### 2.3 离线模式数据流图

```
┌──────────────────────────────────────────────────────────────────────┐
│                        离线检测模式数据流                              │
│                                                                      │
│  config.json                                                         │
│      │                                                               │
│      ▼                                                               │
│  ConfigLoader ──→ FailSlowConfig (Pydantic)                          │
│      │                     │                                         │
│      │               _hydrate_task()                                 │
│      │                     │                                         │
│      │    ┌────────────────┼────────────────────┐                    │
│      │    ▼                ▼                    ▼                    │
│      │  IDataSource   IPpreprocessor[]    IDetector[]               │
│      │  (实例化)       (实例化)            (实例化)                   │
│      │    │                │                    │                    │
│      ▼    ▼                ▼                    ▼                    │
│  Application.start()                                                 │
│      │                                                               │
│      ▼                                                               │
│  DetectionPipeline(data_source=..., ...)                             │
│      │                                                               │
│      ▼                                                               │
│  pipeline.run_offline()                                              │
│      │                                                               │
│      ├─ data_source.connect()                                        │
│      ├─ data_source.read() → Iterator[StepMetrics]                   │
│      │       │                                                       │
│      │       ▼ 按 step 分组                                          │
│      │   steps_buffer: {step_id: [StepMetrics, ...]}                 │
│      │                                                               │
│      ├─ for step_id in sorted(steps_buffer):                         │
│      │       │                                                       │
│      │       ▼                                                       │
│      │   _process_step(step_metrics_list)  ◄── 共用核心方法          │
│      │       │                                                       │
│      │       ├─ data_sink.write() ──── None (离线不落盘)             │
│      │       ├─ MetricExtractor.extract() → DetectorInput            │
│      │       ├─ OpNameFilter.process() → 过滤非目标算子              │
│      │       ├─ TimeWindowAggregator.process() → 聚合                │
│      │       ├─ TimeWindowAggregator.flush() → np.ndarray (T, N)    │
│      │       ├─ Detector.detect() → anomaly_labels (T, N)           │
│      │       └─ AlertReporter.report() → 告警输出                    │
│      │                                                               │
│      └─ data_source.disconnect()                                     │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. 在线检测模式流程

### 3.1 启动流程

```
online_detection.py --config config.json --data-dir /path/to/data --interval 0.1
    │
    ├─ 1. 创建 Task(config_path)
    │      │
    │      ├─ _load_config() → ConfigLoader → 组件实例化
    │      ├─ _create_pipeline() → DetectionPipeline(data_source=None, data_sink=...)
    │      ├─ 启动后台线程 _process_loop()
    │      └─ TaskFactory.register(task_name, task)
    │
    ├─ 2. load_nccl_data(data_dir) → {step_id: [StepMetrics, ...]}
    │
    ├─ 3. for step_id in sorted_steps:
    │      task.on_recv_all_step(steps)  ← 非阻塞，放入队列
    │      time.sleep(interval)
    │
    └─ 4. task.shutdown() → 等待后台线程完成 → 关闭 data_sink
```

### 3.2 Task 异步处理机制

```python
# task.py
class Task(ITask):
    def __init__(self, config_path):
        self._data_queue = queue.Queue()
        self._running = True
        self._processor_thread = threading.Thread(target=self._process_loop, daemon=True)
        self._processor_thread.start()

    def on_recv_all_step(self, step_metrics_list):
        """非阻塞：数据放入队列后立即返回"""
        self._data_queue.put(step_metrics_list)

    def _process_loop(self):
        """后台线程：从队列取数据，按间隔触发检测"""
        step_cache = []
        while self._running:
            current_time = time.time()
            try:
                step_metrics_list = self._data_queue.get(timeout=0.1)
                step_cache.extend(step_metrics_list)
                
                # 检测间隔判断
                if self._detect_interval_seconds <= 0:
                    # 即时模式：有数据就检测
                    if step_cache:
                        self._do_detection(step_cache)
                        step_cache = []
                elif current_time - self._last_detect_time >= self._detect_interval_seconds:
                    # 定时模式：间隔到达后检测
                    self._do_detection(step_cache)
                    self._last_detect_time = current_time
                    step_cache = []
                    
            except queue.Empty:
                # 队列空时也检查是否需要检测（处理缓存数据）
                if step_cache and (detect_interval <= 0 or interval_passed):
                    self._do_detection(step_cache)
                    step_cache = []
```

### 3.3 在线模式数据流图

```
┌──────────────────────────────────────────────────────────────────────┐
│                        在线检测模式数据流                              │
│                                                                      │
│  外部数据源 (CSV/网络/...)                                            │
│      │                                                               │
│      ▼                                                               │
│  task.on_recv_all_step(step_metrics_list)                            │
│      │                                                               │
│      ▼                                                               │
│  _data_queue.put()  ←── 非阻塞，立即返回                              │
│      │                                                               │
│      ▼ (后台线程)                                                     │
│  _process_loop()                                                     │
│      │                                                               │
│      ├─ _data_queue.get() → step_cache.extend()                      │
│      │                                                               │
│      ├─ 检测间隔判断                                                   │
│      │   ├─ interval <= 0: 有数据就检测                               │
│      │   └─ interval > 0: 定时触发检测                                │
│      │                                                               │
│      ▼                                                               │
│  _do_detection(step_cache)                                           │
│      │                                                               │
│      ▼                                                               │
│  pipeline._process_step(step_cache)  ◄── 共用核心方法                 │
│      │                                                               │
│      ├─ data_sink.write() ──── IDataSink (异步落盘)                  │
│      ├─ MetricExtractor.extract() → DetectorInput                    │
│      ├─ OpNameFilter.process() → 过滤非目标算子                       │
│      ├─ TimeWindowAggregator.process() → 增量聚合                     │
│      ├─ TimeWindowAggregator.flush() → np.ndarray (T, N)            │
│      ├─ Detector.detect() → anomaly_labels (T, N)                   │
│      └─ AlertReporter.report() → 告警输出                             │
│                                                                      │
│  task.shutdown()                                                     │
│      ├─ _running = False                                             │
│      ├─ _processor_thread.join()                                     │
│      └─ data_sink.close() → flush() + executor.shutdown()           │
└──────────────────────────────────────────────────────────────────────┘
```

### 3.4 在线模式关键时序

```
时间轴 ─────────────────────────────────────────────────────►

外部调用:  on_recv(s0)  on_recv(s1)  on_recv(s2)      on_recv(s50)
              │            │            │                  │
              ▼            ▼            ▼                  ▼
队列:       [s0]         [s0,s1]     [s0,s1,s2]        [s50]
              │            │            │                  │
              │            │            │                  │
后台线程:   ──┤            ├────────────┤                  ├──────
              │            │            │                  │
           cache=[s0]  cache=[s0,s1,s2]              cache=[s50]
              │            │                              │
              │     5秒间隔到达                    5秒间隔到达
              │            │                              │
              ▼            ▼                              ▼
          _do_detection  _do_detection               _do_detection
          (仅s0数据)    (s0+s1+s2数据)              (s50数据)
```

**注意**：`step_cache` 在检测触发后清空，不会重复处理。但 `TimeWindowAggregator._raw_cache` 会跨调用累积，实现增量聚合。

---

## 4. 共用核心方法 _process_step 详解

`_process_step()` 是两种模式共用的核心处理逻辑，位于 `DetectionPipeline` 中：

```
_process_step(step_metrics_list, task_type, task_name)
    │
    ├─ 1. data_sink.write(step_metrics_list)        ← 在线模式落盘
    │     (deep-copy 防止异步写入+原地修改竞态)
    │
    ├─ 2. MetricExtractor.extract()                  ← 提取指标
    │     输入: List[StepMetrics]
    │     输出: DetectorInput(values, rank_ids, node_ips)
    │     - slow_calc: t4_ns - t3_ns (计算时间)
    │     - slow_launch: t3_ns - t2_ns (启动延迟)
    │     - degradation: end_time_ns - start_time_ns
    │
    ├─ 3. OpNameFilter.process()                     ← 算子过滤
    │     - 统计所有算子出现次数
    │     - 选择最高频算子作为 target_op
    │     - 原地修改 step.kernels，过滤非目标算子
    │     - 返回 None（不产生聚合数据）
    │
    ├─ 4. TimeWindowAggregator.process()             ← 时间窗口聚合
    │     - 将 List[StepMetrics] 按 rank 聚合
    │     - 离线: 全局聚合，缺失填 0
    │     - 在线: 增量聚合到 _raw_cache，缺失填 np.nan
    │     - 返回 None（_process_called_since_flush=True）
    │
    ├─ 5. TimeWindowAggregator.flush()               ← 刷出聚合数据
    │     - 返回 np.ndarray (num_windows, num_ranks)
    │     - 在线模式: _raw_cache 保留，下次继续累积
    │     - 离线模式: 同上
    │
    ├─ 6. Detector.detect()                          ← 异常检测
    │     - 输入: np.ndarray (T, N)
    │     - 输出: np.ndarray (T, N) 异常标签矩阵
    │     - 支持分组检测 (TP/DP/PP)
    │
    └─ 7. AlertReporter.report()                     ← 告警上报
          - 将 DetectionResult 转换为 Alert
          - 通过 Console/File/其他方式输出
```

---

## 5. 关键接口解析

### 5.1 IDataSource — 数据源接口

```python
class IDataSource(ABC):
    def connect(self) -> None: ...       # 建立连接
    def disconnect(self) -> None: ...    # 断开连接
    def is_connected(self) -> bool: ...  # 连接状态
    def read(self) -> Iterator[StepMetrics]: ...  # 读取数据迭代器
```

**使用场景：** 仅离线模式使用。`read()` 返回迭代器，每个 `StepMetrics` 包含 1 个 `KernelType`。

**实现：** `LocalCsvDataSource` — 从本地 CSV 目录读取，支持 NCCL 和 HCCL 两种格式自动检测。

**关键行为：**
- `read()` 内部按文件逐个解析，每个 CSV 行生成一个 `StepMetrics`
- 所有记录的 `step` 被强制设为 0（`record["step"] = 0`）
- HCCL 格式按 `Id` 分组，每组 4 行事件解析为一个 `StepMetrics`

### 5.2 IDataSink — 数据落盘接口

```python
class IDataSink(ABC):
    def write(self, step_metrics_list: List[StepMetrics]) -> None: ...  # 异步写入
    def flush(self) -> None: ...    # 刷盘
    def close(self) -> None: ...    # 关闭释放资源
```

**使用场景：** 仅在线模式使用。在 `_process_step()` 最开始调用，先于预处理和检测。

**实现：** `LocalCsvDataSink` — 异步写入本地 CSV 文件，支持两种格式：
- `"nccl"`: `hccl_activity-{ip}-.{rank}.csv`，时间单位 us
- `"hccl"`: `mspti-marker-{ip}-{rank}.csv`，时间单位 ns

**关键设计：**
- `write()` 使用 `copy.deepcopy()` 防止异步写入与预处理器原地修改的竞态
- 使用 `ThreadPoolExecutor(max_workers=2)` 异步写入
- `_file_lock` 保护文件写入和 `_created_files`/`_next_id` 状态
- HCCL 格式维护 `_next_id: Dict[int, int]` 确保 Id 全局递增不重复

### 5.3 IMetricExtractor — 指标提取接口

```python
class IMetricExtractor(ABC):
    @property
    def name(self) -> str: ...
    
    def extract(self, data: List[StepMetrics]) -> DetectorInput: ...
```

**职责：** 从 `StepMetrics` 中提取特定指标，转换为 `DetectorInput`。

**实现：**

| 实现类 | 提取指标 | 计算方式 |
|--------|---------|---------|
| `SlowCalcMetricExtractor` | 计算时间 | `t4_ns - t3_ns` |
| `SlowLaunchMetricExtractor` | 启动延迟 | `t3_ns - t2_ns` |
| `DegradationMetricExtractor` | 步延迟 | `end_time_ns - start_time_ns` |

**关键行为：**
- `extract()` 是只读操作，不修改输入数据
- 每个 `StepMetrics` 的所有 `kernels` 的指标值都被提取
- 返回的 `DetectorInput.values` 是 1D 数组 `(num_ranks,)`

### 5.4 IPreprocessor — 预处理器接口

```python
class IPreprocessor(ABC):
    def process(self, data: List[StepMetrics], task_type=None) -> np.ndarray: ...
    def flush(self) -> Optional[np.ndarray]: ...
```

**职责：** 将 `List[StepMetrics]` 转换为聚合后的 `np.ndarray (T, N)` 格式供检测器使用。

**实现：**

| 实现类 | 职责 | process() 返回 | flush() 返回 |
|--------|------|----------------|-------------|
| `OpNameFilterPreprocessor` | 过滤非目标算子 | None | None |
| `TimeWindowAggregatorPreprocessor` | 时间窗口聚合 | None | np.ndarray (T, N) |

**OpNameFilterPreprocessor 关键行为：**
- 首次 `process()` 统计算子频率，选择最高频算子
- **原地修改** `step.kernels`，过滤非目标算子
- `get_target_op()` 返回选中的目标算子名称
- `set_target_op()` 允许外部设置目标算子

**TimeWindowAggregatorPreprocessor 关键行为：**
- 离线模式：全局聚合，缺失填 0
- 在线模式：增量聚合到 `_raw_cache`，缺失填 `np.nan`
- `process()` 返回 None（设置 `_process_called_since_flush=True`）
- `flush()` 返回聚合后的 `np.ndarray (num_windows, num_ranks)`
- 支持极值过滤、平滑处理、per-operator 配置

### 5.5 IDetector — 检测器接口层次

```
IDetector (基接口)
│   ├── name: str
│   └── reset() -> None
│
├── IBatchDetector
│   └── detect(data: ndarray|DetectorInput, context=None) -> ndarray
│       输入: (time_len, num_ranks)
│       输出: (time_len, num_ranks) 异常标签 0/1
│
├── IStreamDetector
│   └── detect(data: ndarray|DetectorInput, context=None) -> List[DetectionResult]
│       输入: (num_ranks,) 单步数据
│       输出: 检测结果列表
│
├── IStepMetricsStreamDetector
│   └── detect(data: List[StepMetrics]) -> List[DetectionResult]
│       直接接收 StepMetrics
│
└── IStatefulDetector
    ├── get_state() -> Dict[str, Any]
    └── set_state(state: Dict) -> None
        支持状态持久化/恢复
```

**Pipeline 中的使用：** 当前 Pipeline 使用 `IBatchDetector.detect()` 接口，传入聚合后的 2D 数组。

**CompositeDetector 组合模式：**
```python
class CompositeDetector(IBatchDetector):
    time_detector: IDetector    # 时间维度检测
    space_detector: IDetector   # 空间维度检测
    fusion_strategy: IFusionStrategy  # 融合策略
```

**融合策略：**
- `TimeSpaceFusionStrategy`：优先 space，无异常时用 time
- `OrFusionStrategy`：任一异常即为异常
- `AndFusionStrategy`：两者都异常才为异常

### 5.6 IAlertReporter — 告警上报接口

```python
class IAlertReporter(ABC):
    @property
    def name(self) -> str: ...
    def report(self, alert: Alert) -> bool: ...
    def is_available(self) -> bool: ...
    def convert_to_alert(self, result: DetectionResult) -> Alert: ...
```

**实现：**

| 实现类 | 输出方式 |
|--------|---------|
| `ConsoleReporter` | 控制台打印 |
| `FileReporter` | JSON 文件 |

---

## 6. 配置加载与组件实例化流程

### 6.1 ConfigLoader 完整流程

```
config.json
    │
    ▼ json.load()
config_data: Dict
    │
    ▼ FailSlowConfig(**config_data)
Pydantic 验证 → TaskConfig 列表（组件仍为配置对象）
    │
    ▼ _hydrate_task(task_config)
    │
    ├── data_source: DataSourceConfig → source_factory.create(type, **params)
    │   例: local_csv → LocalCsvDataSource(directory_path=...)
    │
    ├── metric_extractors: [MetricExtractorConfig] → [SlowCalcMetricExtractor()]
    │
    ├── preprocessors: [PreprocessorConfig] → [OpNameFilterPreprocessor(), TimeWindowAggregatorPreprocessor()]
    │
    ├── detectors: [DetectorConfig] → _create_detector_recursive()
    │   ├── 非 composite: detector_factory.create(type, **params)
    │   └── composite: 递归创建 time_detector + space_detector → factory.create("composite", ...)
    │
    ├── alert_reporters: [AlertReporterConfig] → [ConsoleReporter(), FileReporter()]
    │
    └── data_sink: DataSinkConfig → data_sink_factory.create(type, **params)
        例: local_csv → LocalCsvDataSink(output_directory=..., format=...)
```

### 6.2 两种模式的配置差异

**离线模式配置**（`data_source` 存在）：
```json
{
    "data_source": {"type": "local_csv", "params": {"directory_path": "/path/to/data"}},
    "data_sink": null
}
```

**在线模式配置**（`data_source` 为 null）：
```json
{
    "data_source": null,
    "data_sink": {"type": "local_csv", "enabled": true, "params": {"output_directory": "/path/to/sink", "format": "hccl"}}
}
```

---

## 7. 离线 vs 在线模式对比总结

### 7.1 数据处理差异

| 环节 | 离线模式 | 在线模式 |
|------|---------|---------|
| **数据读取** | `IDataSource.read()` 一次性读取 | `on_recv_all_step()` 流式接收 |
| **step 分组** | `run_offline()` 内按 step_id 分组 | `_process_loop` 内按检测间隔分组 |
| **数据落盘** | 不落盘 | `IDataSink.write()` 异步落盘 |
| **聚合方式** | 全局聚合，缺失填 0 | 增量聚合，缺失填 np.nan |
| **检测触发** | 每个 step_id 触发一次 | 按时间间隔触发 |
| **处理线程** | 主线程同步 | 后台线程异步 |

### 7.2 组件差异

| 组件 | 离线模式 | 在线模式 |
|------|---------|---------|
| `data_source` | 必须配置 | 为 None |
| `data_sink` | 不使用 | 可选配置 |
| `Pipeline` 入口 | `run_offline()` | `_process_step()` |
| `Task` | 不创建 | 创建并注册到 TaskFactory |

### 7.3 典型使用场景

**离线模式**：分析历史训练数据，生成检测报告
```bash
python -m failslow.entrypoints.main --config config/config.json
```

**在线模式**：实时监控训练过程，持续检测异常
```bash
python -m failslow.entrypoints.online_detection --config config/config.json --data-dir /path/to/data --interval 0.1
```

---

## 8. 数据落盘格式说明

在线模式支持两种落盘格式，通过 `data_sink.params.format` 配置：

### 8.1 NCCL 格式 (format="nccl")

- 文件名: `hccl_activity-{node_ip}-.{rank_id}.csv`
- 列: `kernel,t1,t2,t3,t4,step`
- 时间单位: 微秒 (us)
- 每个 kernel 一行

### 8.2 HCCL 格式 (format="hccl")

- 文件名: `mspti-marker-{node_ip}-{rank_id}.csv`
- 列: `Flag,Id,Kind,Name,SourceKind,Timestamp,msptiObjectId_Ds_DeviceId,...`
- 时间单位: 纳秒 (ns)
- 每个 kernel 生成 4 行事件:
  - `Flag=16, SourceKind=0` → Host Start (t1)
  - `Flag=16, SourceKind=1` → Device Start (t3)
  - `Flag=32, SourceKind=1` → Device End (t4)
  - `Flag=32, SourceKind=0` → Host End (t2, 仅当 t2 > 0)
- Name 字段格式: `comm:{kernel_name}!{node_ip}!0!0`
- Id 全局递增，跨写入批次不重复

### 8.3 落盘数据可回放

两种格式的落盘数据均可通过 `LocalCsvDataSource` 重新读取，用于离线检测验证。
