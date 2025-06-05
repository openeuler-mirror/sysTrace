# README

`LD_PRELOAD=./build/libmspti_tracker.so python xxx`



# 调优记录
1 250506调优记录：
数据尺度在5-8ms,调整dbscann的eps
eps: 0.4 -> 0.04
window_size: 100 -> 20
## 0510 通信慢检测对象，
**检测规则**:
1 一个通信组内会有batchsendrecv, 目前考虑按照数据特征分开，再分别检测，
2 在收尾的慢通信对需要结合其他通信域的检测结果；

## todo
1 算子下发检测算法优化
2 所有算子的检测配置文件更改
3 调测出rpm包

1 package name: sysTrace-failslow

# 安装部署
## 前置条件
支持的python版本：3.7+；
failslow 依赖于 systrace 采集的数据通信算子数据，请先完成 训练任务的 通信算子采集；
failslow 直接从本地目录读取通信算子数据，需要在配置文件中指定通信算子数据的路径

## 从本仓库源码安装运行（适用于开发者）
### 下载源码
 git clone https://gitee.com/openeuler/sysTrace.git
### 安装
工程./systrace目录下执行下面命令：
python3 setup.py install
### 运行
systrace-failslow

### 数据分析
**算子执行**：3ms左右，计算慢导致的异常时7-8ms
**算子下发**: 表示算子下发到算子开始执行的时间 600ms左右
**通信慢**: sendrecv：几十ms到1200ms