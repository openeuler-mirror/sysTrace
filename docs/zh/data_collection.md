# 数据采集

## 背景

在 AI 训练过程中，性能问题和故障诊断是关键挑战。为了实现对训练过程的全面监控和问题定位，sysTrace 需要采集多维度的性能数据。数据采集是 sysTrace 功能实现的基础，通过收集 torch_npu 层、CANN 层、MSPTI 通信算子以及系统级事件等数据，为后续的性能分析和故障诊断提供原始素材。

数据采集模块的主要作用包括：

- 实时捕获训练过程中的关键性能指标
- 记录可能导致性能问题的异常事件
- 为性能劣化检测和慢卡定位提供数据支撑
- 帮助用户深入了解训练任务的资源使用情况和执行状态

## 数据采集方式

sysTrace 通过 `LD_PRELOAD` 方式将动态库加载到 AI 训练任务中，实现对训练过程的无侵入式数据采集：

### 方式一：使用低版本 libunwind（< 1.7）

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

### 方式二：使用高版本 libunwind（>= 1.7）

如果环境中的 libunwind 版本大于等于 1.7，使用以下命令：

```bash
LD_PRELOAD=/home/ascend-toolkit-bak/ascend-toolkit/8.0.RC3.10/tools/mspti/lib64/libmspti.so:<path-to-sysTrace>/systrace/build/libsysTrace.so python ...
```
