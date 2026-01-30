# sysTrace采集使用指南
## 1、前置条件
参考[部署指南](./0.quickstart.md)安装部署sysTrace

## 2、使用方法
项目编译完成后，在build目录中存在 sysTrace_cli 可执行程序
~~~bash
./sysTrace_cli -h
=========================================================
USAGE:
  sysTrace_cli <action> <plugin> [key=value ...]

ACTIONS:
  enable   Start or update a plugin's configuration
  disable  Stop a plugin and flush data to disk

COMMON PARAMETERS:
  duration=<sec>    - Capture duration in seconds (0 for infinite)

PLUGINS & SPECIFIC PARAMETERS:
  MSPTI       NVIDIA/Atlas Activity Tracing (HCCL, Kernels)
    event=<types>   - Comma-separated: marker, kernel, api

  IO          Disk and Network I/O Latency/Throughput

  CPU         CPU Utilization and Context Switch Trace

  Memory      Memory Allocation and Leak Detection

  CacheMiss   Hardware Cache Miss Rates and Memory Access Efficiency
    args=-p <pid> -e <events> --timeout <ms>- Standard perf-stat arguments for hardware event monitoring

  GIL         Python Global Interpreter Lock (GIL) Contention and Latency Trace
    pid=<pid>       - trace target python process

  Mutex       Pthread Synchronization Latency (Mutex/RWLock/Spinlock/Sem)
    pid=<pid>       - trace target process

EXAMPLES:
  sysTrace_cli enable MSPTI event=marker,kernel,api duration=10
  sysTrace_cli enable IO duration=10
  sysTrace_cli enable Memory duration=10
  sysTrace_cli enable CacheMiss duration=10 args="-p 12345 -e cache-miss"
  sysTrace_cli enable GIL duration=10
  sysTrace_cli enable Mutex duration=10
  sysTrace_cli enable CacheMiss args=" -e branch-misses,cache-misses,cache-references --timeout 5000" duration=10
  sysTrace_cli disable CPU
=========================================================
~~~

## 3、功能列表
| plugin    |                           适用场景                           |                                                     命令示例 |
| :-------- | :----------------------------------------------------------: | -----------------------------------------------------------: |
| HBM       |                           HBM事件                            |                        ./sysTrace_cli enable HBM duration=10 |
| IO        |           Disk and Network I/O Latency/Throughput            |                         ./sysTrace_cli enable IO duration=10 |
| MSPTI     |        NVIDIA/Atlas Activity Tracing (HCCL, Kernels)         |                      ./sysTrace_cli enable MSPTI duration=10 |
| CPU       |           CPU Utilization and Context Switch Trace           |                        ./sysTrace_cli enable CPU duration=10 |
| Memory    |             Memory Allocation and Leak Detection             |                     ./sysTrace_cli enable Memory duration=10 |
| GIL       | Python Global Interpreter Lock (GIL) Contention and Latency Trace |                       ./sysTrace_cli enable GIL  duration=10 |
| CacheMiss |    Hardware Cache Miss Rates and Memory Access Efficiency    | ./sysTrace_cli enable CacheMiss args="-p 27638 -e branch-misses,cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,L1-icache-load-misses,L1-icache-loads --timeout 20000" |
| Mutex     | Pthread Synchronization Latency (Mutex/RWLock/Spinlock/Sem)  |                      ./sysTrace_cli enable Mutex duration=10 |

## 4、使用示例
### 4.1 HBM
~~~bash
# 采集指令
./sysTrace_cli enable HBM duration=10

# 指令发送成功
[ACK] /tmp/sysTrace_1868164.sock: SUCCESS
[ACK] /tmp/sysTrace_1868165.sock: SUCCESS

# 日志查看   tail -f /var/log/sysTrace/sysTrace_latest.log
[2026-01-30 09:40:33.868] [Control] [RANK 0] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"HBM"}
[2026-01-30 09:40:33.868] [Control] [RANK 0] [INFO] Enabling plugin: HBM with params: {"duration":"10"}
[2026-01-30 09:40:33.868] [HBM] [RANK 0] [INFO] HBM trace started.
[2026-01-30 09:40:33.869] [Control] [RANK 0] [INFO] Response sent: SUCCESS
[2026-01-30 09:40:33.869] [Control] [RANK 1] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"HBM"}
[2026-01-30 09:40:33.869] [Control] [RANK 1] [INFO] Enabling plugin: HBM with params: {"duration":"10"}
[2026-01-30 09:40:33.869] [HBM] [RANK 1] [INFO] HBM trace started.
[2026-01-30 09:40:33.870] [Control] [RANK 1] [INFO] Response sent: SUCCESS
[2026-01-30 09:40:43.869] [HBM] [RANK 0] [INFO] HBM trace stopped.
[2026-01-30 09:40:43.870] [HBM] [RANK 1] [INFO] HBM trace stopped.

#采集结果
[root@localhost hbm_trace]# pwd
/home/sysTrace/hbm_trace
[root@localhost hbm_trace]# ll
total 64
-rw-r--r-- 1 root root 30900 Jan 30 09:40 hbm_trace_rank0_1868164.pb
-rw-r--r-- 1 root root 30684 Jan 30 09:40 hbm_trace_rank1_1868165.pb
~~~


### 4.2 IO

~~~bash
# 采集指令
./sysTrace_cli enable IO duration=10

# 指令发送成功
[ACK] /tmp/sysTrace_1868164.sock: SUCCESS
[ACK] /tmp/sysTrace_1868165.sock: SUCCESS

# 日志查看   tail -f /var/log/sysTrace/sysTrace_latest.log
[2026-01-30 09:45:40.106] [Control] [RANK 0] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"IO"}
[2026-01-30 09:45:40.107] [Control] [RANK 0] [INFO] Enabling plugin: IO with params: {"duration":"10"}
[2026-01-30 09:45:40.107] [IO] [RANK 0] [INFO] IO trace started.
[2026-01-30 09:45:40.107] [Control] [RANK 0] [INFO] Response sent: SUCCESS
[2026-01-30 09:45:40.107] [Control] [RANK 1] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"IO"}
[2026-01-30 09:45:40.108] [Control] [RANK 1] [INFO] Enabling plugin: IO with params: {"duration":"10"}
[2026-01-30 09:45:40.108] [IO] [RANK 1] [INFO] IO trace started.
[2026-01-30 09:45:40.108] [Control] [RANK 1] [INFO] Response sent: SUCCESS
[2026-01-30 09:45:50.107] [IO] [RANK 0] [INFO] IO trace stopped.
[2026-01-30 09:45:50.108] [IO] [RANK 1] [INFO] IO trace stopped.

#采集结果
[root@localhost io_trace]# pwd
/home/sysTrace/io_trace
[root@localhost io_trace]# ll
total 60
-rw-r--r-- 1 root root 42450 Jan 30 09:45 io_trace_rank0_1868164.pb
-rw-r--r-- 1 root root 12629 Jan 30 09:45 io_trace_rank1_1868165.pb
~~~


### 4.3 MSPTI
~~~bash
# 采集指令
./sysTrace_cli enable MSPTI duration=10

# 指令发送成功
[ACK] /tmp/sysTrace_1868164.sock: SUCCESS
[ACK] /tmp/sysTrace_1868165.sock: SUCCESS

# 日志查看   tail -f /var/log/sysTrace/sysTrace_latest.log
[2026-01-30 09:48:37.849] [Control] [RANK 0] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"MSPTI"}
[2026-01-30 09:48:37.849] [Control] [RANK 0] [INFO] Enabling plugin: MSPTI with params: {"duration":"10"}
[2026-01-30 09:48:37.850] [Control] [RANK 0] [INFO] Response sent: SUCCESS
[2026-01-30 09:48:37.850] [Control] [RANK 1] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"MSPTI"}
[2026-01-30 09:48:37.850] [Control] [RANK 1] [INFO] Enabling plugin: MSPTI with params: {"duration":"10"}
[2026-01-30 09:48:37.851] [Control] [RANK 1] [INFO] Response sent: SUCCESS
[2026-01-30 09:48:37.879] [MSPTI] [RANK 0] [INFO] Enabled Activity Kind: 1
[2026-01-30 09:48:37.908] [MSPTI] [RANK 1] [INFO] Enabled Activity Kind: 1
[2026-01-30 09:48:47.885] [MSPTI] [RANK 0] [INFO] Disabled Activity Kind: 1
[2026-01-30 09:48:47.914] [MSPTI] [RANK 1] [INFO] Disabled Activity Kind: 1

#采集结果
[root@localhost mspti]# pwd
/home/sysTrace/mspti
[root@localhost mspti]# ll
total 1288
-rw-r--r-- 1 root root 658179 Jan 30 09:48 mspti-marker-76.53.151.141-0.csv
-rw-r--r-- 1 root root 658179 Jan 30 09:48 mspti-marker-76.53.151.141-1.csv
~~~


### 4.4 CPU
~~~bash
# 采集指令
./sysTrace_cli enable CPU duration=10

# 指令发送成功
[ACK] /tmp/sysTrace_1868164.sock: SUCCESS
[ACK] /tmp/sysTrace_1868165.sock: SUCCESS

# 日志查看   tail -f /var/log/sysTrace/sysTrace_latest.log
[2026-01-30 09:51:23.697] [Control] [RANK 0] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"CPU"}
[2026-01-30 09:51:23.697] [Control] [RANK 0] [INFO] Enabling plugin: CPU with params: {"duration":"10"}
[2026-01-30 09:51:23.698] [CPU] [RANK 0] [INFO] CPU trace started.
[2026-01-30 09:51:23.698] [Control] [RANK 0] [INFO] Response sent: SUCCESS
[2026-01-30 09:51:23.698] [Control] [RANK 1] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"CPU"}
[2026-01-30 09:51:23.699] [Control] [RANK 1] [INFO] Enabling plugin: CPU with params: {"duration":"10"}
[2026-01-30 09:51:23.699] [CPU] [RANK 1] [INFO] CPU trace started.
[2026-01-30 09:51:23.699] [Control] [RANK 1] [INFO] Response sent: SUCCESS
[2026-01-30 09:51:33.698] [CPU] [RANK 0] [INFO] CPU trace stopped.
[2026-01-30 09:51:33.700] [CPU] [RANK 1] [INFO] CPU trace stopped.

#采集结果 (CPU采集结果落盘和Memory为同一个文件)
[root@localhost osprobe]# pwd
/home/sysTrace/osprobe
[root@localhost osprobe]# ll
total 260
-rw-r--r-- 1 root root 128010 Jan 30 09:51 os_trace_20260130_09_rank_0_1868164.pb
-rw-r--r-- 1 root root 133567 Jan 30 09:51 os_trace_20260130_09_rank_1_1868165.pb
~~~


### 4.5 Memory

~~~bash
# 采集指令
./sysTrace_cli enable Memory duration=10

# 指令发送成功
[ACK] /tmp/sysTrace_1868164.sock: SUCCESS
[ACK] /tmp/sysTrace_1868165.sock: SUCCESS

# 日志查看   tail -f /var/log/sysTrace/sysTrace_latest.log
[2026-01-30 10:06:01.392] [Control] [RANK 0] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"Memory"}
[2026-01-30 10:06:01.392] [Control] [RANK 0] [INFO] Enabling plugin: Memory with params: {"duration":"10"}
[2026-01-30 10:06:01.392] [Memory] [RANK 0] [INFO] Memory trace started.
[2026-01-30 10:06:01.393] [Control] [RANK 0] [INFO] Response sent: SUCCESS
[2026-01-30 10:06:01.393] [Control] [RANK 1] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"Memory"}
[2026-01-30 10:06:01.393] [Control] [RANK 1] [INFO] Enabling plugin: Memory with params: {"duration":"10"}
[2026-01-30 10:06:01.394] [Memory] [RANK 1] [INFO] Memory trace started.
[2026-01-30 10:06:01.394] [Control] [RANK 1] [INFO] Response sent: SUCCESS
[2026-01-30 10:06:11.393] [Memory] [RANK 0] [INFO] Memory trace stopped.
[2026-01-30 10:06:11.394] [Memory] [RANK 1] [INFO] Memory trace stopped.

#采集结果 (Memory采集结果落盘和CPU为同一个文件)
[root@localhost osprobe]# pwd
/home/sysTrace/osprobe
[root@localhost osprobe]# ll
total 260
-rw-r--r-- 1 root root 128010 Jan 30 09:51 os_trace_20260130_09_rank_0_1868164.pb
-rw-r--r-- 1 root root 133567 Jan 30 09:51 os_trace_20260130_09_rank_1_1868165.pb
~~~

### 

### 4.6 GIL

~~~bash
#示例一，默认采集AI主进程（运行在NPU卡上的主进程 npu-smi info） GIL信息
# 采集指令 
./sysTrace_cli enable GIL duration=10

# 指令发送成功
[ACK] /tmp/sysTrace_1901644.sock: SUCCESS
[ACK] /tmp/sysTrace_1901645.sock: SUCCESS

# 日志查看   tail -f /var/log/sysTrace/sysTrace_latest.log
[2026-01-30 10:34:45.138] [Control] [RANK 0] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"GIL"}
[2026-01-30 10:34:45.139] [Control] [RANK 0] [INFO] Enabling plugin: GIL with params: {"duration":"10"}
[2026-01-30 10:34:45.269] [GIL] [RANK 0] [INFO] Output file: /home/sysTrace/GIL/GIL_1901644_rank_0.json
[2026-01-30 10:34:45.269] [Control] [RANK 0] [INFO] Response sent: SUCCESS
[2026-01-30 10:34:45.270] [Control] [RANK 1] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"GIL"}
[2026-01-30 10:34:45.270] [Control] [RANK 1] [INFO] Enabling plugin: GIL with params: {"duration":"10"}
[2026-01-30 10:34:45.270] [Control] [RANK 1] [INFO] Response sent: SUCCESS
[2026-01-30 10:34:55.591] [GIL] [RANK 0] [INFO]  trace stop.

#采集结果 (GIL多卡数据已聚合到同一文件)
[root@localhost GIL]# pwd
/home/sysTrace/GIL
[root@localhost GIL]# ll
total 9884
-rw-r--r-- 1 root root 10120449 Jan 30 10:34 GIL_1901644_rank_0.json

#示例二，通过pid参数同时采集指定pid GIL信息。多个pid用,分隔。
# 采集指令 
./sysTrace_cli enable GIL duration=10 pid=1907448

# 指令发送成功
[ACK] /tmp/sysTrace_1901644.sock: SUCCESS
[ACK] /tmp/sysTrace_1901645.sock: SUCCESS

# 日志查看   tail -f /var/log/sysTrace/sysTrace_latest.log
[2026-01-30 10:37:28.187] [Control] [RANK 0] [INFO] Received cmd: {"action":"enable","params":{"duration":"10","pid":"1907448"},"path":"GIL"}
[2026-01-30 10:37:28.188] [Control] [RANK 0] [INFO] Enabling plugin: GIL with params: {"duration":"10","pid":"1907448"}
[2026-01-30 10:37:28.260] [GIL] [RANK 0] [INFO] Output file: /home/sysTrace/GIL/GIL_1901644_rank_0.json
[2026-01-30 10:37:28.260] [Control] [RANK 0] [INFO] Response sent: SUCCESS
[2026-01-30 10:37:28.260] [Control] [RANK 1] [INFO] Received cmd: {"action":"enable","params":{"duration":"10","pid":"1907448"},"path":"GIL"}
[2026-01-30 10:37:28.261] [Control] [RANK 1] [INFO] Enabling plugin: GIL with params: {"duration":"10","pid":"1907448"}
[2026-01-30 10:37:28.261] [Control] [RANK 1] [INFO] Response sent: SUCCESS
[2026-01-30 10:37:38.661] [GIL] [RANK 0] [INFO]  trace stop.

#采集结果 (GIL多卡数据已聚合到同一文件)，可上传到 https://www.ui.perfetto.dev/ 进行分析
[root@localhost GIL]# pwd
/home/sysTrace/GIL
[root@localhost GIL]# ll
total 13172
-rw-r--r-- 1 root root 13487979 Jan 30 10:37 GIL_1901644_rank_0.json
~~~

### 

### 4.7 CacheMiss

~~~bash
# 采集指令 参数说明 args -e 必选 采集事件; --timeout 必选 采集时长单位毫秒; 可选-p 指定pid 
./sysTrace_cli enable CacheMiss args=" -e branch-misses,cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,L1-icache-load-misses,L1-icache-loads,LLC-load-misses,LLC-loads,dTLB-load-misses,dTLB-loads,iTLB-load-misses,iTLB-loads,context-switches,r6013,r6014,r7004,r7005,r7006,r7007,r5023,r102e,r102f,r27,r16,r60d6,r007c,r0008,r0011 --timeout 5000"

# 指令发送成功
[ACK] /tmp/sysTrace_1901644.sock: SUCCESS
[ACK] /tmp/sysTrace_1901645.sock: SUCCESS

# 日志查看   tail -f /var/log/sysTrace/sysTrace_latest.log
[2026-01-30 11:02:11.697] [Control] [RANK 0] [INFO] Received cmd: {"action":"enable","params":{"args":" -e branch-misses,cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,L1-icache-load-misses,L1-icache-loads,LLC-load-misses,LLC-loads,dTLB-load-misses,dTLB-loads,iTLB-load-misses,iTLB-loads,context-switches,r6013,r6014,r7004,r7005,r7006,r7007,r5023,r102e,r102f,r27,r16,r60d6,r007c,r0008,r0011 --timeout 5000"},"path":"CacheMiss"}
[2026-01-30 11:02:11.698] [Control] [RANK 0] [INFO] Enabling plugin: CacheMiss with params: {"args":" -e branch-misses,cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,L1-icache-load-misses,L1-icache-loads,LLC-load-misses,LLC-loads,dTLB-load-misses,dTLB-loads,iTLB-load-misses,iTLB-loads,context-switches,r6013,r6014,r7004,r7005,r7006,r7007,r5023,r102e,r102f,r27,r16,r60d6,r007c,r0008,r0011 --timeout 5000"}
[2026-01-30 11:02:11.698] [CacheMiss] [RANK 0] [INFO]  Output file: /home/sysTrace/CacheMiss/CacheMiss_1935088_rank_0.txt
[2026-01-30 11:02:11.764] [Control] [RANK 0] [INFO] Response sent: SUCCESS
[2026-01-30 11:02:11.765] [Control] [RANK 1] [INFO] Received cmd: {"action":"enable","params":{"args":" -e branch-misses,cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,L1-icache-load-misses,L1-icache-loads,LLC-load-misses,LLC-loads,dTLB-load-misses,dTLB-loads,iTLB-load-misses,iTLB-loads,context-switches,r6013,r6014,r7004,r7005,r7006,r7007,r5023,r102e,r102f,r27,r16,r60d6,r007c,r0008,r0011 --timeout 5000"},"path":"CacheMiss"}
[2026-01-30 11:02:11.766] [Control] [RANK 1] [INFO] Enabling plugin: CacheMiss with params: {"args":" -e branch-misses,cache-misses,cache-references,L1-dcache-load-misses,L1-dcache-loads,L1-icache-load-misses,L1-icache-loads,LLC-load-misses,LLC-loads,dTLB-load-misses,dTLB-loads,iTLB-load-misses,iTLB-loads,context-switches,r6013,r6014,r7004,r7005,r7006,r7007,r5023,r102e,r102f,r27,r16,r60d6,r007c,r0008,r0011 --timeout 5000"}
[2026-01-30 11:02:11.766] [Control] [RANK 1] [INFO] Response sent: SUCCESS
[2026-01-30 11:02:17.492] [CacheMiss] [RANK 0] [INFO]  stop.

#采集结果
[root@localhost CacheMiss]# pwd
/home/sysTrace/CacheMiss
[root@localhost CacheMiss]# ll
total 4
-rw-r--r-- 1 root root 2885 Jan 30 11:02 CacheMiss_1935088_rank_0.txt

cat  /home/sysTrace/CacheMiss/CacheMiss_1935088_rank_0.txt
# started on Fri Jan 30 11:02:12 2026


 Performance counter stats for 'system wide':

         148649047      branch-misses                                                 (46.29%)
         195212952      cache-misses              #    0.857 % of all cache refs      (46.34%)
       22788535562      cache-references                                              (46.37%)
         196172754      L1-dcache-load-misses     #    0.85% of all L1-dcache accesses  (46.41%)
       23176613281      L1-dcache-loads                                               (46.44%)
         368753847      L1-icache-load-misses     #    2.11% of all L1-icache accesses  (46.46%)
       17451707150      L1-icache-loads                                               (46.48%)
         138700751      LLC-load-misses           #   43.21% of all LL-cache accesses  (46.50%)
         321000567      LLC-loads                                                     (46.51%)
         163158545      dTLB-load-misses          #    0.60% of all dTLB cache accesses  (46.53%)
       27021471325      dTLB-loads                                                    (46.55%)
          71692354      iTLB-load-misses          #    0.41% of all iTLB cache accesses  (46.57%)
       17324837727      iTLB-loads                                                    (43.01%)
            535323      context-switches
         631181416      r6013                                                         (42.97%)
          63274468      r6014                                                         (42.93%)
       23130888827      r7004                                                         (42.90%)
         796116934      r7005                                                         (42.87%)
       10139211440      r7006                                                         (42.84%)
        9701271710      r7007                                                         (42.83%)
        2285448540      r5023                                                         (42.81%)
        1026604354      r102e                                                         (42.80%)
         151411659      r102f                                                         (42.79%)
         328150439      r27                                                           (42.78%)
        1521606094      r16                                                           (42.78%)
         413642923      r60d6                                                         (42.77%)
          16126045      r007c                                                         (42.75%)
       61314085780      r0008                                                         (42.73%)
       69243999676      r0011                                                         (46.28%)

       5.015744890 seconds time elapsed
~~~

### 

### 4.7 Mutex

~~~bash
#采集的事件如下：
#define PTHREAD_MUTEX_LOCK_NAME         "pthread_mutex_lock"
#define PTHREAD_MUTEX_TIMEDLOCK_NAME    "pthread_mutex_timedlock"
#define PTHREAD_MUTEX_TRYLOCK_NAME      "pthread_mutex_trylock"
#define PTHREAD_RWLOCK_RDLOCK_NAME      "pthread_rwlock_rdlock"
#define PTHREAD_RWLOCK_WRLOCK_NAME      "pthread_rwlock_wrlock"
#define PTHREAD_RWLOCK_TIMEDRDLOCK_NAME "pthread_rwlock_timedrdlock"
#define PTHREAD_RWLOCK_TIMEDWRLOCK_NAME "pthread_rwlock_timedwrlock"
#define PTHREAD_RWLOCK_TRYRDLOCK_NAME   "pthread_rwlock_tryrdlock"
#define PTHREAD_RWLOCK_TRYWRLOCK_NAME   "pthread_rwlock_trywrlock"
#define PTHREAD_SPIN_LOCK_NAME          "pthread_spin_lock"
#define PTHREAD_SPIN_TRYLOCK_NAME       "pthread_spin_trylock"
#define PTHREAD_TIMEDJOIN_NP_NAME       "pthread_timedjoin_np"
#define PTHREAD_TRYJOIN_NP_NAME         "pthread_tryjoin_np"
#define PTHREAD_YIELD_NAME              "pthread_yield"
#define SEM_TIMEDWAIT_NAME              "sem_timedwait"
#define SEM_TRYWAIT_NAME                "sem_trywait"
#define SEM_WAIT_NAME                   "sem_wait"

#示例一，默认采集AI主进程（运行在NPU卡上的主进程 npu-smi info）Mutex信息
# 采集指令 
./sysTrace_cli enable Mutex duration=10

# 指令发送成功
[ACK] /tmp/sysTrace_1901644.sock: SUCCESS
[ACK] /tmp/sysTrace_1901645.sock: SUCCESS

# 日志查看   tail -f /var/log/sysTrace/sysTrace_latest.log
[2026-01-30 10:48:10.497] [Control] [RANK 0] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"Mutex"}
[2026-01-30 10:48:10.498] [Control] [RANK 0] [INFO] Enabling plugin: Mutex with params: {"duration":"10"}
[2026-01-30 10:48:10.583] [Mutex] [RANK 0] [INFO] Output file: /home/sysTrace/Mutex/Mutex_1901644_rank_0.json
[2026-01-30 10:48:10.583] [Control] [RANK 0] [INFO] Response sent: SUCCESS
[2026-01-30 10:48:10.583] [Control] [RANK 1] [INFO] Received cmd: {"action":"enable","params":{"duration":"10"},"path":"Mutex"}
[2026-01-30 10:48:10.584] [Control] [RANK 1] [INFO] Enabling plugin: Mutex with params: {"duration":"10"}
[2026-01-30 10:48:10.584] [Control] [RANK 1] [INFO] Response sent: SUCCESS
[2026-01-30 10:48:20.583] [Mutex] [RANK 0] [INFO] trace stop.

#采集结果 (Mutex多卡数据已聚合到同一文件)
[root@localhost Mutex]# pwd
/home/sysTrace/Mutex
[root@localhost Mutex]# ll
total 856
-rw-r--r-- 1 root root 872775 Jan 30 10:48 Mutex_1901644_rank_0.json

#示例二，通过pid参数同时采集指定pid Mutex信息。多个pid用,分隔。
# 采集指令 
./sysTrace_cli enable Mutex duration=10 pid=1907448

# 指令发送成功
[ACK] /tmp/sysTrace_1901644.sock: SUCCESS
[ACK] /tmp/sysTrace_1901645.sock: SUCCESS

# 日志查看   tail -f /var/log/sysTrace/sysTrace_latest.log
[2026-01-30 10:53:19.845] [Control] [RANK 0] [INFO] Received cmd: {"action":"enable","params":{"duration":"10","pid":"1907448"},"path":"Mutex"}
[2026-01-30 10:53:19.845] [Control] [RANK 0] [INFO] Enabling plugin: Mutex with params: {"duration":"10","pid":"1907448"}
[2026-01-30 10:53:19.950] [Mutex] [RANK 0] [INFO] Output file: /home/sysTrace/Mutex/Mutex_1901644_rank_0.json
[2026-01-30 10:53:19.951] [Control] [RANK 0] [INFO] Response sent: SUCCESS
[2026-01-30 10:53:19.951] [Control] [RANK 1] [INFO] Received cmd: {"action":"enable","params":{"duration":"10","pid":"1907448"},"path":"Mutex"}
[2026-01-30 10:53:19.951] [Control] [RANK 1] [INFO] Enabling plugin: Mutex with params: {"duration":"10","pid":"1907448"}
[2026-01-30 10:53:19.951] [Control] [RANK 1] [INFO] Response sent: SUCCESS
[2026-01-30 10:53:29.950] [Mutex] [RANK 0] [INFO] trace stop.

#采集结果 (Mutex多卡数据已聚合到同一文件)，可上传到 https://www.ui.perfetto.dev/ 进行分析
[root@localhost Mutex]# pwd
/home/sysTrace/Mutex
[root@localhost Mutex]# ll
total 716
-rw-r--r-- 1 root root 729376 Jan 30 10:53 Mutex_1901644_rank_0.json
~~~


