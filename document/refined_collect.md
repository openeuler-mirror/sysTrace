## 总体架构图

```mermaid
graph TD
    %% 外部层
    subgraph "External Control"
        CLI[sysTrace_cli] -- "1. 用户输入命令" --> Trans[JSON Generator]
    end

    %% 通信层
    Trans -- "2. 发送 JSON (via UDS)" --> IPC_Server[Monitor Server]

    %% 注入进程内部
    subgraph "AI Target Process"
        IPC_Server -- "3. 接收字符串" --> Parser[JSON Universal Parser]
        
        subgraph "Control Plane"
            Parser -- "4. 提取 Path & Params" --> Manager[Control Manager]
            Manager -- "5. 查找/调用" --> Registry{Plugin Registry}
        end

        subgraph "Plugin Pool"
            Registry --> P1(L1.MSPTI)
            Registry --> P2(L2.HBM Collector)
            Registry --> P3(L3.CPU Collector)
            Registry --> P4(L3.MEM Collector)
        end

        subgraph "Data Plane"
            sysTrace主进程 -- "6. 产生原始数据" --> Queue[Lock-free Event Queue]
            Queue --> Dispatcher[Event Dispatcher]
            Dispatcher -- "7. 分发采集需要的参数" --> P1 & P2 & P3 & P4
        end

        P1 & P2 & P3 & P4 -- "8. 格式化输出" --> Formatter[Data Formatter]
        Formatter --> Output[(Log File / Shared Memory)]
    end

    %% 样式
    style CLI fill:#f96,stroke:#333
    style Registry fill:#69f,stroke:#fff,stroke-width:2px
    style P4 stroke-dasharray: 5 5
```

## 客户端设计：

- **命令格式：** `sysTrace_cli <action> <path> [key=value ...]`

- **JSON 组装逻辑：**

  ```c
  {
      "action": "enable",           # 动作：enable, disable, status, update
      "module": "L3.MEM",             
      "params": {                   # 动态参数：无需在框架层定义
          "interval": "100s",
          "stack": "true"
      }
  }
  ```

## 服务端设计：

### 类图

```mermaid
classDiagram
    class MonitorServer {
        -int server_fd
        -string socket_path
        -ControlManager& manager
        +start_listen_thread()
        -handle_client(int client_fd)
    }

    class ControlManager {
        -unordered_map~string, shared_ptr~ICollector~~ registry
        +register_plugin(shared_ptr~ICollector~ col)
        +process_command(string raw_json)
        -dispatch(json data)
    }

    class ICollector {
        <<interface>>
        -bool is_active
        +get_id() string*
        +start(json params)* bool
        +stop()* void
        +get_status() bool
    }

    class L3MemCollector {
        -int sample_rate
        -bool stack_trace
        +start(json params) bool
        +stop() void
    }

    class L3CPUCollector {
        -struct bpf_object* skel
        -int filter_pid
        +start(json params) bool
        +stop() void
    }

    class L3GPUMonitor {
        -int device_id
        +start(json params) bool
        +stop() void
    }

    MonitorServer --> ControlManager : 分发指令
    ControlManager "1" o-- "0..*" ICollector : 管理插件生命周期
    ICollector <|-- L3MemCollector : 继承并实现 
    ICollector <|-- L3CPUCollector : 继承并实现 
    ICollector <|-- L3GPUMonitor : 继承并实现 (未来扩展)
```

#### **MonitorServer**

- **职责**：启动一个独立的 POSIX 线程，监听 `sysTrace_cli` 的连接。

#### **ControlManager**

- **职责**：解析json，模块化使能采集功能。
- **关键属性**：如 `L3.mem.leak`）。通过这个 Map，它实现了 **O(1)** 复杂度的插件定位。
- **扩展性：新增采集模块功能时，仅需要注册对象。

#### **ICollector **

- **职责**：定义了插件的基本信息。
- **参数设计**：`start(json params)`。直接使用`json`对象，动态扩展，只保留共有的功能。
  - 不同插件 可以从param中取所需的参数

#### **采集模块实现类**

- **L3MemCollector**：按需采集`pagefault`事件。

- **L3CPUCollector**：按需采集`offcpu`,`oncpu`事件等。

**服务端和客户端通过本地socket通信，这个会和多个实例绑定，一个实例一个socket，**

## 序列图

```mermaid
sequenceDiagram
    participant User as 用户 (CLI)
    participant UDS as UDS Socket
    participant CM as ControlManager
    participant Registry as PluginRegistry
    participant Plugin as L3MemCollector

    User->>UDS: 发送 {"path":"L3.MEM","action":"enable","params":{"interval":2s, ...}}
    UDS->>CM: 接收并传递原始字符串
    CM->>CM: nlohmann::json::parse() 序列化
    CM->>Registry: find("L3.MEM")
    Registry-->>CM: 返回插件实例指针
    CM->>Plugin: start(json_params)
    Plugin->>Plugin: 执行按需采集逻辑
    CM-->>User: 返回执行结果 (OK)
```