# 安装 sysTrace

## 硬软件要求

**操作系统：** openEuler -- 内核版本 5.10.0 +

**软件版本：**

- CANN 8.0RC3
- torch 2.1.0
- torch_npu 2.1.0.post10

## 安装 sysTrace

### 下载源码

```bash
git clone https://gitcode.com/openeuler/sysTrace.git
```

### 安装依赖包

#### openEuler 系统

```bash
## 软件包版本要求：libbpf >= 0.8.1, clang >= 10.0.0, gcc >= 8.3.0, bpftool >= 6.8.0 libunwind >=1.7
## 如果版本均满足则跳过下面的安装依赖步骤
yum install gcc g++ cmake make python3-devel protobuf-compiler protobuf-devel protobuf-c-devel libbpf clang libbpf-devel bpftool elfutils-devel elfutils-libelf-devel nlohmann-json-devel libunwind libunwind-devel
```

### 安装依赖

安装 sysTrace 依赖libbpf、 bpftool。如果系统自带的libbpf、 bpftool 版本不满足要求（libbpf >= 0.8.1，bpftool >= 6.8.0），需要手动安装。

#### 安装 libbpf

```bash
git clone https://github.com/libbpf/libbpf.git
cd libbpf
git checkout v0.8.1
cd src
make && make install
```

#### 安装 bpftool

```bash
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool
git submodule update --init
cd src
make && make install
```

### 编译项目

sysTrace 支持两种数据格式：pb（protobuf）和 json。编译时可以选择不同的格式：

**编译为 pb 格式（默认）：**

```bash
cd sysTrace
bash build.sh
```

**编译为 json 格式：**

```bash
cd sysTrace
bash build.sh --mode=json
```

**关闭默认python采集**

```bash
cd sysTrace
bash build.sh --python-tracing=off
```

**编译产物说明：**

编译产物均在 `build` 目录下，主要用到 `libsysTrace.so`（用于LD_PRELOAD挂载） 和 `sysTrace_cli`（命令行工具）

```bash
# ll build/
total 1776
-rw-r--r--. 1 root root   17000 Jun 12 16:58 CMakeCache.txt
drwxr-xr-x. 7 root root    4096 Jun 12 17:10 CMakeFiles
-rw-r--r--. 1 root root    1798 Jun 12 16:58 cmake_install.cmake
-rw-r--r--. 1 root root  534270 Jun 12 17:10 libcommon.a
-rwxr-xr-x. 1 root root 1209296 Jun 12 17:10 libsysTrace.so
-rw-r--r--. 1 root root   20479 Jun 12 17:10 Makefile
drwxr-xr-x. 3 root root    4096 Jun 12 17:10 protos
-rwxr-xr-x. 1 root root   76736 Jun 12 17:10 sysTrace_cli
```
