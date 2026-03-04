# 数据落盘

## 背景

在 AI 训练性能监控与故障诊断过程中，实时采集的数据需要持久化存储，以便进行后续的离线分析、性能劣化检测和故障定位。数据落盘是 sysTrace 功能链中的关键环节，它将内存中临时存储的各类性能数据（如 torch_npu 调用栈、CANN 层内存信息、MSPTI 通信算子数据、系统级事件等）保存到磁盘，为后续的数据分析和可视化提供原始素材。

数据落盘功能的主要作用包括：

- 实现数据的持久化存储，避免训练过程中数据丢失
- 支持多卡数据的独立存储和管理
- 为离线分析和故障诊断提供完整的数据基础
- 便于在集群环境中收集和汇总多节点数据

## 存储位置与结构

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
