# systrace-failslow

<!-- markdownlint-disable MD013 -->

`systrace-failslow` 是 sysTrace 面向 AI 训练场景下的数据分析模块，用于识别训练中的性能劣化，并定界慢卡、慢节点问题（包括算子计算慢和算子下发慢）。

## AI 训练中的典型问题场景

### 1. 性能劣化场景

训练任务虽未中断，但单个 Step 耗时逐渐增加，导致整体吞吐持续下降，训练周期明显延长。此类问题常见于资源争抢、系统抖动、数据加载波动或通信链路退化。现场排查时，建议优先进行 Step 时延劣化检测，以确认任务是否已进入“整体变慢”状态。

### 2. 慢卡慢节点算子计算慢场景

在分布式同步训练中，若某张卡、某个节点明显慢于其他卡、其他节点，整个训练进度就会被最慢的一侧拖累。其典型表现为：特定卡、节点的算子执行时间持续偏高。可以把这类检测理解为定位“哪张卡、哪个节点的算子执行慢”。

### 3. 慢卡慢节点算子下发慢场景

训练卡顿未必来源于算子执行慢，也可能是算子从框架侧下发到设备侧的启动阶段出现延迟。其典型表现为：算子创建后到实际开始执行前的等待时间明显更长。可以把这类检测理解为定位“哪张卡、哪个节点的算子下发慢”。

### 4. 建议的排查顺序

现场排查时，建议先看任务是不是整体变慢，再看是否存在慢卡、慢节点或算子计算慢；如果没有明显的慢卡、慢节点或算子计算慢结果，但训练仍然明显卡顿，再继续排查算子下发慢。

## 三个入口命令及职责边界

| 命令 | 入口代码 | 主要用途 |
|------|----------|----------|
| `systrace-failslow` | `failslow.entrypoints.main:main` | 用于单机或单节点的本地独立分析，直接读取本地配置和本地数据 |
| `systrace-failslow-server` | `failslow.entrypoints.multi_node_server:main` | 运行在中心节点，接收各上报节点的数据并统一执行多节点检测 |
| `systrace-failslow-agent` | `failslow.entrypoints.multi_node_agent:main` | 运行在每个上报节点，扫描本地 CSV 数据并上报给中心节点上的检测服务 |

## 单机场景使用方式

`systrace-failslow` 只有一个必选参数 `--config`，实际检测类型由配置文件决定。

```bash
# Step 时延劣化检测
systrace-failslow --config /etc/systrace/config/config.degradation_ksigma_robust.json

# Step 时延劣化检测（BOCPD 变点检测）
systrace-failslow --config /etc/systrace/config/config.degradation_bocpd.json

# 慢卡 / 慢节点 / 算子计算慢检测
systrace-failslow --config /etc/systrace/config/config.slow_calc.json

# 算子下发慢检测
systrace-failslow --config /etc/systrace/config/config.slow_launch.json
```

## 多机场景使用方式

多机场景下，如果需要把多个节点上的本地 CSV 数据汇聚到中心节点统一分析，不论是慢卡 / 慢节点 / 算子计算慢，还是算子下发慢，通常都使用中心节点上的 `systrace-failslow-server` 加各上报节点上的 `systrace-failslow-agent` 这一套模式。

```bash
# 中心节点启动多节点慢卡 / 慢节点 / 算子计算慢检测服务
systrace-failslow-server \
  --config /etc/systrace/config/config.multi_node_slow_calc.json \
  --host 0.0.0.0 \
  --port 8765

# 中心节点启动多节点算子下发慢检测服务
systrace-failslow-server \
  --config /etc/systrace/config/config.multi_node_slow_launch.json \
  --host 0.0.0.0 \
  --port 8765

# 需要监控预期节点时，可额外声明 expected-nodes
systrace-failslow-server \
  --config /etc/systrace/config/config.multi_node_degradation_ksigma_robust.json \
  --port 8765 \
  --expected-nodes '{"10.0.0.1": 8, "10.0.0.2": 8}'

# 训练节点启动数据上报代理
systrace-failslow-agent \
  --server-url http://10.2.44.100:8765 \
  --data-dir /home/sysTrace/mspti \
  --node-ip 10.2.44.104
```

说明：

- `systrace-failslow-server` 的 `--config` 为必选参数，`--host` 默认 `0.0.0.0`，`--port` 默认 `8765`。
- `--expected-nodes` 为可选 JSON 字符串，例如 `'{"10.0.0.1": 8, "10.0.0.2": 8}'`，主要用于状态监控和缺失节点判断，不控制检测周期。
- 服务端对外提供 `/api/v1/step_metrics`、`/api/v1/health`、`/api/v1/status` 三个 HTTP 接口。
- `systrace-failslow-agent` 主要用于需要由各节点本地持续扫描 CSV 并主动上报到中心节点的场景；如果现场已经有现成的数据汇聚方式，也可以直接调用服务端 `/api/v1/step_metrics` 接口上报数据。直接上报仅适用于已经按服务端 `StepMetrics` 序列化格式组织数据的兼容上报方；顶层 JSON 需要包含 `node_ip` 和 `step_metrics_list`，其中 `step_metrics_list` 内每个元素也必须完整符合服务端期望的 `StepMetrics` 字段结构。
- Agent 侧至少需要提供 `--server-url` 和 `--data-dir`；`--node-ip` 不填时会自动探测，`--data-format`、`--data-source`、`--interval`、`--max-retries`、`--retry-delay` 可按现场需要调整。

## 关键配置文件与常用参数

### 1. 按场景选择配置文件

| 使用场景 | 推荐配置文件 | 说明 |
|----------|--------------|------|
| Step 时延劣化检测 | `config.degradation_ksigma_robust.json` | 本地读取 `training-step-time-*.csv`，基于鲁棒 k-sigma 判断训练是否出现整体性能劣化 |
| Step 时延劣化检测（`BOCPD`） | `config.degradation_bocpd.json` | 本地读取 `training-step-time-*.csv`，基于在线变点检测判断 Step 时延分布是否发生劣化 |
| 算子计算慢检测 | `config.slow_calc.json` | 本地读取 `HCCL/NCCL CSV`，定位训练执行路径上的算子计算慢的卡和节点 |
| 算子下发慢检测 | `config.slow_launch.json` | 本地读取 `HCCL/NCCL CSV`，定位训练执行路径上的算子下发慢的卡和节点 |
| 多节点 Step 时延劣化检测 | `config.multi_node_degradation_ksigma_robust.json` | 中心服务接收各节点数据后，基于鲁棒 k-sigma 统一做 Step 时延劣化检测 |
| 多节点 Step 时延劣化检测（`BOCPD`） | `config.multi_node_degradation_bocpd.json` | 中心服务接收各节点数据后，基于 `BOCPD` 统一做 Step 时延劣化检测 |
| 多节点慢卡 / 慢节点 / 算子计算慢检测 | `config.multi_node_slow_calc.json` | 中心服务统一处理多节点上报的算子执行数据 |
| 多节点算子下发慢检测 | `config.multi_node_slow_launch.json` | 中心服务统一处理多节点上报的 launch 数据 |

### 2. 检测算法说明

#### degradation_bocpd

`degradation_bocpd` 使用 Bayesian Online Changepoint Detection（`BOCPD`）对每个 rank 的 Step 时延序列做在线变点检测。算法持续维护当前运行长度的后验概率，当 Step 时延分布出现持续上升变点时输出劣化告警。该算法适合发现“从某个时间点开始整体变慢”的场景，对基线缓慢变化和不同 rank 的历史差异更友好。常用参数包括：

- `distribution`：概率分布模型，默认配置可使用 `StudentTProb1d` 或 `LinearProb1dWithRunLengthBonus`。
- `hazard`：变点先验概率，值越大越容易触发变点。
- `min_consecutive`：同一方向变点连续出现多少次后确认告警。
- `detect_rise` / `detect_drop`：控制检测时延上升或下降；性能劣化通常只开启 `detect_rise`。

#### degradation_ksigma_robust

`degradation_ksigma_robust` 使用滑动窗口内的中位数和 MAD（Median Absolute Deviation）估计历史基线，并按 `median +/- k_sigma * MAD` 形成阈值带。单个 rank 的 Step 时延超过阈值带，且相对偏离程度达到 `anomaly_degree_thr` 后，会形成一次异常信号；连续达到 `min_consecutive` 次才确认劣化。该算法计算开销低、可解释性强，适合现场快速判断 Step 时延是否持续升高。常用参数包括：

- `window_size`：初始滑动窗口长度。
- `k_sigma`：阈值倍数，值越大越保守。
- `anomaly_degree_thr`：相对偏离阈值，用于过滤轻微波动。
- `use_variable_window` 和 `window_increase_ratio`：控制窗口未满时是否提前检测，以及窗口增长速度。

#### sliding_window_ksigma

`sliding_window_ksigma` 用于慢卡、慢节点、算子计算慢和算子下发慢定界检测。算法先对多 rank 时间序列做极值过滤、平滑和按时间点的中位数归一化，再用滑动窗口计算每个 rank 的上下界，并根据 `slow_type` 判断异常方向：`slow_cal` 关注执行耗时偏低或进展偏慢的计算异常，`slow_launch` 和 `slow_host` 关注 launch 或主机侧耗时偏高异常。检测结果还会结合连续异常长度、置信度累计和尾部保留策略，避免把全体 rank 同步变化误判为单卡或单节点问题。常用参数包括：

- `k` 和 `look_back`：控制 k-sigma 阈值和初始窗口长度。
- `slow_type`：指定慢计算、慢下发、主机侧慢或双向检测模式。
- `anom_threshold`：确认告警所需的连续异常次数。
- `change_conf`：当过多 rank 同时异常时重置窗口，降低全局波动误报。
- `alert_conf_thresh`、`conf_score_decay` 和 `deviation_ratio_thresh`：控制告警置信度和偏离幅度门限。

## 输出结果说明

### 1. 结果默认输出位置

默认把告警结果写入 `/home/sysTrace/local/output/`。常见输出文件包括：

- 性能劣化检测：`/home/sysTrace/local/output/degradation_alerts.json`
- 多节点 Step 时延劣化检测：`/home/sysTrace/local/output/degradation_alerts.json`
- 慢卡 / 慢节点 / 算子计算慢检测：`/home/sysTrace/local/output/slow_calc_alerts.json`
- 主机侧慢节点检测：`/home/sysTrace/local/output/slow_host_alerts.json`
- 算子下发慢检测：`/home/sysTrace/local/output/slow_launch_alerts.json`
- 多节点慢卡 / 慢节点 / 算子计算慢检测：`/home/sysTrace/local/output/multi_node_slow_calc_alerts.json`
- 多节点算子下发慢检测：`/home/sysTrace/local/output/multi_node_slow_launch_alerts.json`

如果现场已经调整过配置，最终结果路径以 `alert_reporters.file.params.output_path` 为准。

### 2. 结果样例说明

下面是一个慢卡慢节点算子计算慢结果样例。结果文件按行写入 JSON，对同一文件中的每一行都可以按下面方式解读：

```json
{
  "anomaly_type": "calc_slow",
  "severity": "warning",
  "details": {
    "abnormal_ranks": [3],
    "abnormal_ips": ["10.2.44.104"],
    "anomaly_time_ranges": [
      {
        "start": 1771941016721,
        "end": 1771941067721
      }
    ],
    "detect_type": "SPACE"
  }
}
```

- `anomaly_type`：异常类型。现场可先据此判断是性能劣化、算子执行慢还是算子下发慢。
- `details.abnormal_ranks`：异常 rank 列表，先看这里定位是哪几个 rank 变慢。
- `details.abnormal_ips`：异常节点 IP 列表，用于快速定位到具体机器。
- `details.anomaly_time_ranges`：异常时间段列表，每个元素包含 `start` 和 `end`，表示异常区间。
- `details.detect_type`：检测维度。常见值如 `SPACE`，表示主要按空间维度比较不同 rank 或节点。
