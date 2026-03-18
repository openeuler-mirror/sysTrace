# 背景

在 AI 训练过程中，性能问题和故障是影响训练效率和成本的关键因素。尽管 sysTrace 能够采集多维度的性能数据，但这些原始数据本身并不能直接揭示训练过程中的问题。数据分析模块是 sysTrace 的核心智能组件，它通过先进的算法对采集到的各类数据进行深度分析，实现对训练性能的实时监控、异常检测和故障定位。  

AI 训练面临的主要性能挑战包括：  

训练过程中的性能突然劣化（FailSlow），导致训练时间显著增加  
多卡/多节点训练环境下的性能不一致，存在"慢卡"问题  

数据分析模块的主要作用包括：  

实时监测训练性能指标，及时发现性能劣化和异常  
精确定位导致性能问题的具体节点、算子或系统资源  

# sysTrace_cli

## 工具说明

`sysTrace_cli` 是 sysTrace 项目自带的命令行工具，用于与训练/推理任务中的 sysTrace 服务通信，控制各采集项的启停。

## 使用方式

通过设置`LD_PRELOAD` 环境变量将 `libsysTrace.so` 动态库加载到 AI 推理/训练任务中，从而启用 sysTrace 的数据采集功能。  
其中torch_npu 层的 Python 函数调用栈是常开的，不需要手动开启。

## 采集项列表

| Plugin    | 适用场景                                           | 命令示例                                                     |
| :-------- | :------------------------------------------------- | :----------------------------------------------------------- |
| IO        | 磁盘和网络I/O延迟/吞吐量                           | `sysTrace_cli enable IO duration=10`                       |
| MSPTI     | Atlas活动跟踪（HCCL，内核）                 | `sysTrace_cli enable MSPTI duration=10`                    |

### IO 数据格式

采集磁盘和网络 I/O 延迟/吞吐量数据。

**数据格式：** pb/json

### MSPTI 数据格式

采集 Atlas 活动跟踪数据，包括通信算子下发/执行信息，用于判断是否发生算子慢的情况。

**数据格式：** CSV

**数据字段：**

```python
Flag,Id,Kind,Name,SourceKind,Timestamp,msptiObjectId_Ds_DeviceId,msptiObjectId_Ds_StreamId,msptiObjectId_Pt_ProcessId,msptiObjectId_Pt_ThreadId
```
