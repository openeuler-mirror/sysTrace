# systrace-failslow

AI训练性能异常检测功能，用于检测和定位AI训练中的慢节点和性能劣化问题。

## 功能概述

systrace-failslow 提供两大核心检测能力：

### 1. 慢节点感知

性能劣化是 AI 训练中常见的性能问题，表现为训练过程中某个或某些步骤的执行时间突然显著增加，导致整体训练效率下降，需要检测训练过程中的性能劣化问题：

#### 1.1 Step 时延劣化检测

- 实时监控每个 step 的执行时间  
- 使用 SlidingWindowKSigmaRobust 算法检测时延异常  
- 支持按 rank 独立检测  

### 2. 慢节点检测

在多卡或多节点分布式训练环境中，"慢卡"问题是导致训练效率下降的主要原因之一。由于硬件差异、资源竞争、网络拥塞等因素，不同节点或卡的训练速度可能出现不一致，最终导致整个训练任务被最慢的卡拖慢（木桶效应）。，需要检测训练过程中执行速度明显慢于其他节点的设备（慢节点）。

**检测原理**：  

- 解析 MSPTI (Memory System Performance Tracking Interface) 采集的通信算子数据  
- 从 CSV 文件中提取每个算子的 4 个时间戳点 (t1, t2, t3, t4)：  
  - `t1`: 算子创建时间  
  - `t2`: 算子下发时间  
  - `t3`: 算子开始执行时间  
  - `t4`: 算子执行完成时间  
- 计算执行时间 `t_exec = t4 - t3`  
- 使用滑动窗口 + K-Sigma 算法检测异常节点  

**数据来源**：  
`mspti-marker-{IP}-{rank}.csv`  

## 快速开始

### 运行

```bash
# 启用劣化感知
systrace-failslow --remote-hosts [ip] --ssh-port [port] --enable-fail-slow  

# 启用慢节点检测
systrace-failslow --remote-hosts [ip] --ssh-port [port] --enable-slow-node  
```

### 命令行参数

| 参数 | 说明 | 默认值 |
|-----|------|-------|
| `--metric-path` | MSPTI/Step Time 数据目录 | `/home/sysTrace/mspti` |
| `--detection-interval` | 检测间隔(秒) | 60 |
| `--remote-hosts` | 远程主机列表(逗号分隔) | None |
| `--ssh-port` | SSH 端口 | 22 |
| `--enable-slow-node` | 启用慢节点检测 | False |
| `--enable-fail-slow` | 启用劣化感知 | False |

## 配置说明

### 主配置文件

配置文件位于 `/etc/systrace/config/config.json`、`/etc/systrace/config/model_config.json`、`/etc/systrace/config/metric_config.json`
