# README

# 安装部署
## 前置条件
支持的python版本：3.7+；
failslow 依赖于 systrace 采集的数据通信算子数据，请先完成 训练任务的 通信算子采集；

failslow-mcpserver 支持本地或者远程获取远程目标服务器的systrace 采集的通信算子数据，需要在配置文件中指定通信算子数据的路径。
failslow-openapi 支持本地或者远程获取远程目标服务器的systrace 采集的通信算子数据，需要在配置文件中指定通信算子数据的路径。

## 从本仓库源码安装运行（适用于开发者）
### 下载源码
 git clone https://gitee.com/openeuler/sysTrace.git
### 安装 failslow
工程./systrace目录下执行下面命令：
python3 setup.py install
### 运行
systrace-failslow

### 安装mcpserver
工程./systrace/systrace_mcp目录下执行下面命令：
python3 setup.py install
### 运行
systrace-mcpserver #开启mcp server服务 服务端口为 12145

systrace-openapi #开启openapi server服务 服务端口 12146


配置远程获取数据，修改./config/ftp_config.json文件
~~~json
{
  "servers": [
    {
      "ip": "192.168.122.196",  #远程目标服务器的ip
      "port": 22, #远程目标服务器的ssh端口
      "user": "root", #用户名
      "password": "Huawei12#$", #密码
      "perception_remote_dir": "/home/hx/sysTrace_dataloader/timeline", #远程目标服务器systrace采集的timeline数据保存路径
      "detection_remote_dir": "/home/hx/sysTrace_dataloader/mspti",#远程目标服务器systrace采集的mspti数据保存路径
    }
  ],
  "enable": "False" #True 为开启远程获取数据，False为关闭只使用本地文件进行分析
}

~~~


### 数据分析
**算子执行**：3ms左右，计算慢导致的异常时7-8ms
**算子下发**: 表示算子下发到算子开始执行的时间 600ms左右
**通信慢**: sendrecv：几十ms到1200ms