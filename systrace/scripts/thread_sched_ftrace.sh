#!/bin/bash
set -euo pipefail

TRACEFS="/sys/kernel/tracing"
OUTPUT_JSON="ftrace_ai_trace.json"
FOCUS_EVENT="sched_switch"
TRACE_PIPE="$TRACEFS/trace_pipe"
EVENT_QUEUE=()
QUEUE_MAX=1000
LOCK_FILE="/tmp/sched_collect.lock"
TARGET_CPU=-1   # 过滤CPU（默认-1：保留全部；指定数字如129：仅保存该CPU）
LOG_LEVEL="normal"  # 日志级别：normal（默认）/ debug（打印所有日志）

declare -A pid_start_time  
declare -A pid_comm        
script_start_ns=0         
script_start_utc_ms=0      
first_event=1         
JSON_INITED=0
CLEANUP_RUNNING=0

safe_write() {
    local file="$1"
    local content="$2"
    [ -w "$file" ] && echo "$content" > "$file" 2>/dev/null && return 0
    echo "[WARN] 警告：$file 不可写，跳过"
    return 1
}

get_kernel_uptime_ns() {
    cut -d' ' -f1 /proc/uptime | tr ',' '.' | awk '{print int($1 * 1000000000)}'
}

get_current_utc_ms() {
    date -u +%s%3N  
}

safe_parse_cpu() {
    local cpu_str="$1"
    printf "%d" "$cpu_str" 2>/dev/null || echo "0"
}

log_debug() {
    if [ "$LOG_LEVEL" = "debug" ]; then
        echo "$@"
    fi
}

log_warn() {
    if [ "$LOG_LEVEL" = "debug" ] && [[ "$1" =~ "CPU核心号解析异常" ]]; then
        echo "$@"
    elif [[ ! "$1" =~ "CPU核心号解析异常" ]]; then
        echo "$@"
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --cpu)
                TARGET_CPU="$2"
                if ! [[ "$TARGET_CPU" =~ ^-?[0-9]+$ ]]; then
                    echo "[ERROR] --cpu 参数必须是整数（默认-1：保留全部CPU，指定具体CPU号如129）"
                    exit 1
                fi
                shift 2
                ;;
            --output|-o)  
                OUTPUT_JSON="$2"
                if [ -z "$OUTPUT_JSON" ]; then
                    echo "[ERROR] --output/-o 参数不能为空，请指定有效的文件名（如 trace.json）"
                    exit 1
                fi
                local output_dir=$(dirname "$OUTPUT_JSON")
                [ -d "$output_dir" ] || mkdir -p "$output_dir" 2>/dev/null || {
                    echo "[ERROR] 无法创建输出目录 $output_dir（权限不足或路径无效）"
                    exit 1
                }
                shift 2
                ;;
            --debug)
                LOG_LEVEL="debug"
                echo "[INFO] 日志级别：DEBUG（打印所有详细日志）"
                shift 1
                ;;
            -h|--help)
                echo "用法：$0 [选项]"
                echo "选项："
                echo "  --cpu <CPU号>   只保存指定CPU的事件到JSON（默认-1：保存全部CPU）"
                echo "                  示例：$0 --cpu 129（仅保存CPU129的事件）"
                echo "  --output|-o <文件名>  指定输出JSON文件名（默认：ftrace_ai_trace.json）"
                echo "                      示例：$0 -o my_trace.json 或 $0 --output custom.json"
                echo "  --debug         启用DEBUG日志模式（打印收到事件、过滤日志等）"
                echo "  -h, --help      显示帮助信息"
                exit 0
                ;;
            *)
                echo "[ERROR] 未知参数：$1"
                echo "使用 -h 或 --help 查看用法"
                exit 1
                ;;
        esac
    done

    if [ "$TARGET_CPU" -eq -1 ]; then
        echo "[INFO] 过滤配置：保留全部CPU的事件"
    else
        echo "[INFO] 过滤配置：仅保存CPU $TARGET_CPU 的事件到JSON"
    fi
    echo "[INFO] 输出文件：$OUTPUT_JSON"
    echo "[INFO] 日志级别：$( [ "$LOG_LEVEL" = "debug" ] && echo "DEBUG" || echo "NORMAL（仅打印关键信息）" )"
}

check_tracefs_mounted() {
    echo -e "\n[INFO] === 检查tracefs ==="
    if [ -d "$TRACEFS" ] && [ -f "$TRACE_PIPE" ] && [ -f "$TRACEFS/available_events" ]; then
        echo "[INFO] tracefs 已挂载，trace_pipe 存在"
        return 0
    fi
    echo "[INFO] 尝试挂载tracefs..."
    mkdir -p "$TRACEFS" 2>/dev/null
    mount -t tracefs nodev "$TRACEFS" 2>/dev/null && [ -f "$TRACE_PIPE" ] && {
        echo "[INFO] tracefs 挂载成功"
        return 0
    }
    echo -e "\n[ERROR] 错误：trace_pipe 不存在！手动挂载："
    echo "sudo mkdir -p $TRACEFS && sudo mount -t tracefs nodev $TRACEFS"
    exit 1
}

verify_ftrace_config() {
    echo -e "\n[INFO] === 验证配置 ==="
    grep -q "$FOCUS_EVENT" "$TRACEFS/available_events" 2>/dev/null || {
        echo "[ERROR] 内核不支持 $FOCUS_EVENT 事件"
        exit 1
    }
    [ -r "$TRACE_PIPE" ] || {
        echo "[ERROR] trace_pipe 不可读（需root权限运行）"
        exit 1
    }
    echo "[INFO] 配置验证通过"
}

ensure_json_complete() {
    local temp_file=$(mktemp)
    if [ ! -f "$OUTPUT_JSON" ]; then
        echo '{"traceEvents":[]}' > "$OUTPUT_JSON"
        log_warn "[WARN] JSON文件不存在，已创建空完整JSON"
        return 0
    fi

    sed -e '/^[[:space:]]*$/d' -e 's/,$//' "$OUTPUT_JSON" > "$temp_file"

    if ! grep -q ']}' "$temp_file"; then
        echo -e "\n]}" >> "$temp_file"
    fi

    mv -f "$temp_file" "$OUTPUT_JSON"
    chmod 644 "$OUTPUT_JSON"
}

process_event_queue() {
    local queue_len=${#EVENT_QUEUE[@]}
    local i=0
    while [ $i -lt $queue_len ]; do
        local line="${EVENT_QUEUE[$i]}"
        local processed=0
        local prev_comm="unknown"
        local prev_state="unknown"
        local prev_pid="0"  # 原进程PID（作为tid）
        local next_comm="unknown"
        local next_pid="0"
        local cpu_str="0" 
        local cpu="0"   
        local event_ts_float=""
        local event_kernel_uptime_ns=""
        local event_utc_ms=""  # JSON的ts字段（UTC毫秒）
        local start_kernel_uptime_ns=""
        local dur_us=""        # JSON的dur字段（微秒）
        local json_str=""
        local sec=""
        local usec=""
        local key=""
        local prev_key=""

        if [[ "$line" =~ prev_comm=([^ ]+) ]]; then
            prev_comm="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" =~ prev_pid=([0-9]+) ]]; then
            prev_pid="${BASH_REMATCH[1]}"  # 这是要作为tid的原进程PID
        fi
        if [[ "$line" =~ prev_state=([A-Za-z0-9_]+) ]]; then
            prev_state="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" =~ next_comm=([^ ]+) ]]; then
            next_comm="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" =~ next_pid=([0-9]+) ]]; then
            next_pid="${BASH_REMATCH[1]}"
        fi
        if [[ "$line" =~ \[([0-9]+)\] ]]; then
            cpu_str="${BASH_REMATCH[1]}"  # 提取原始CPU字符串（可能带前导零，如088）
        fi
        if ! [[ "$line" =~ ([0-9]+\.[0-9]+): ]]; then
            log_debug "[DEBUG] 无时间戳事件，跳过：$line"
            unset "EVENT_QUEUE[$i]"
            EVENT_QUEUE=("${EVENT_QUEUE[@]}")
            queue_len=${#EVENT_QUEUE[@]}
            continue
        fi
        event_ts_float="${BASH_REMATCH[1]}"

        cpu=$(safe_parse_cpu "$cpu_str")
        if [ "$cpu" -eq 0 ] && [ "$cpu_str" != "0" ] && [ "$cpu_str" != "000" ]; then
            log_warn "[WARN] CPU核心号解析异常：原始字符串=$cpu_str → 解析后=$cpu（跳过该事件）"
            unset "EVENT_QUEUE[$i]"
            EVENT_QUEUE=("${EVENT_QUEUE[@]}")
            queue_len=${#EVENT_QUEUE[@]}
            continue
        fi

        if [ "$TARGET_CPU" -ne -1 ] && [ "$cpu" -ne "$TARGET_CPU" ]; then
            log_debug "[DEBUG] 过滤掉非目标CPU事件：CPU$cpu（目标CPU：$TARGET_CPU）"
            unset "EVENT_QUEUE[$i]"
            EVENT_QUEUE=("${EVENT_QUEUE[@]}")
            queue_len=${#EVENT_QUEUE[@]}
            continue
        fi

        sec=$(echo "$event_ts_float" | cut -d'.' -f1)
        usec=$(echo "$event_ts_float" | cut -d'.' -f2)
        usec=$(echo "$usec" | awk '{printf "%06d", int($0)}')
        event_kernel_uptime_ns=$(echo "$sec $usec" | awk '{print $1 * 1000000000 + $2 * 1000}')

        key="${next_pid}:${cpu}" 
        if [ "$next_pid" -ne 0 ]; then
            if [ -z "${pid_comm[$next_pid]-}" ]; then
                pid_comm[$next_pid]="$next_comm"
                log_debug "[DEBUG] 记录进程名：${pid_comm[$next_pid]}($next_pid)"
            fi
            if [ -z "${pid_start_time[$key]-}" ]; then
                pid_start_time[$key]="$event_kernel_uptime_ns"
                local delta_ms=$(echo "$event_kernel_uptime_ns $script_start_ns" | awk '{print int(($1 - $2)/1000000)}')
                local start_utc_ms=$(( script_start_utc_ms + delta_ms ))
                log_debug "[DEBUG] 记录启动：${pid_comm[$next_pid]}($next_pid) @ CPU$cpu（原始字符串：$cpu_str） | UTC时间：$start_utc_ms ms | 存储键：$key"
            fi
            unset "EVENT_QUEUE[$i]"
            EVENT_QUEUE=("${EVENT_QUEUE[@]}")
            queue_len=${#EVENT_QUEUE[@]}
            processed=1
        fi

        if [ "$processed" -eq 0 ] && [ "$prev_pid" -ne 0 ]; then
            prev_key="${prev_pid}:${cpu}"
            if [ -n "${pid_start_time[$prev_key]-}" ] && [ -n "${pid_comm[$prev_pid]-}" ]; then
                start_kernel_uptime_ns="${pid_start_time[$prev_key]}"
                local prev_comm_stored="${pid_comm[$prev_pid]}"

                local delta_ms=$(echo "$start_kernel_uptime_ns $script_start_ns" | awk '{print int(($1 - $2)/1000000)}')
                event_utc_ms=$(( script_start_utc_ms + delta_ms ))
                dur_us=$(echo "$event_kernel_uptime_ns $start_kernel_uptime_ns" | awk '{
                    dur = ($1 - $2)/1000;
                    print dur < 1 ? 1 : int(dur + 0.5);
                }')

                prev_comm_stored=$(echo "$prev_comm_stored" | sed -e 's/"/\\"/g' -e 's/\n/\\n/g')
                next_comm=$(echo "$next_comm" | sed -e 's/"/\\"/g' -e 's/\n/\\n/g')

                if [ "$JSON_INITED" -eq 0 ]; then
                    echo '{"traceEvents":[' > "$OUTPUT_JSON"
                    JSON_INITED=1
                fi

                if [ "$first_event" -eq 1 ]; then
                    json_str=$(printf '{"name":"%s","cat":"sched","ph":"X","pid":"%s","tid":"%s","ts":"%s","dur":"%s","args":{"prev_comm":"%s","prev_pid":"%s","prev_state":"%s","next_comm":"%s","next_pid":"%s","cpu":"%s"}}' \
                        "${prev_comm_stored}" "${cpu}" "${prev_pid}" "$((event_utc_ms))" "${dur_us}" \
                        "${prev_comm_stored}" "${prev_pid}" "${prev_state}" "${next_comm}" "${next_pid}" "${cpu}")
                    first_event=0
                else
                    json_str=$(printf ',{"name":"%s","cat":"sched","ph":"X","pid":"%s","tid":"%s","ts":"%s","dur":"%s","args":{"prev_comm":"%s","prev_pid":"%s","prev_state":"%s","next_comm":"%s","next_pid":"%s","cpu":"%s"}}' \
                        "${prev_comm_stored}" "${cpu}" "${prev_pid}" "$((event_utc_ms))" "${dur_us}" \
                        "${prev_comm_stored}" "${prev_pid}" "${prev_state}" "${next_comm}" "${next_pid}" "${cpu}")
                fi

                log_debug "  CPU核心（pid）：$cpu（原始字符串：$cpu_str） | 原进程PID（tid）：$prev_pid | 进程名：$prev_comm_stored"
                log_debug "  UTC时间戳（ts）：$event_utc_ms ms（$(date -u -d @$((event_utc_ms/1000)) +'%Y-%m-%d %H:%M:%S').$((event_utc_ms%1000))）"
                log_debug "  持续时长（dur）：$dur_us us"
                log_debug "[DEBUG] JSON事件内容：$json_str"
                echo "$json_str" >> "$OUTPUT_JSON"

                unset "pid_start_time[$prev_key]"
                unset "EVENT_QUEUE[$i]"
                EVENT_QUEUE=("${EVENT_QUEUE[@]}")
                queue_len=${#EVENT_QUEUE[@]}
                processed=1
            else
                log_debug "[DEBUG] 未找到 $prev_comm($prev_pid) 在CPU$cpu（原始字符串：$cpu_str）的启动记录（跳过）"
                unset "EVENT_QUEUE[$i]"
                EVENT_QUEUE=("${EVENT_QUEUE[@]}")
                queue_len=${#EVENT_QUEUE[@]}
                processed=1
            fi
        fi

        if [ "$processed" -eq 0 ]; then
            i=$((i + 1))
            if [ $queue_len -gt $QUEUE_MAX ]; then
                log_debug "[DEBUG] 事件队列已满（$QUEUE_MAX），移除最旧未处理事件"
                unset "EVENT_QUEUE[0]"
                EVENT_QUEUE=("${EVENT_QUEUE[@]}")
                queue_len=${#EVENT_QUEUE[@]}
            fi
        else
            i=0  
        fi
    done
}

read_events() {
    stdbuf -i0 -o0 cat "$TRACE_PIPE" 2>/dev/null | while IFS='' read -r line; do
        if [[ "$line" =~ "sched_switch" ]]; then
            log_debug -e "\n[DEBUG] 收到事件：$line"
            EVENT_QUEUE+=("$line")
            process_event_queue
        fi
    done
}

start_collection() {
    echo -e "\n[INFO] 开始采集，按Ctrl+C停止（仅需按一次）..."

    read_events &
    local read_pid=$!

    while true; do
        if [ ${#EVENT_QUEUE[@]} -gt 0 ]; then
            process_event_queue
        fi
        sleep 0.1
    done

    wait $read_pid
}

cleanup() {
    # 防止重复执行清理流程（多次按Ctrl+C时）
    if [ "$CLEANUP_RUNNING" -eq 1 ]; then
        echo -e "\n[WARN] 清理流程已在执行中，请勿重复按Ctrl+C！"
        return
    fi
    CLEANUP_RUNNING=1

    echo -e "\n-------------------------------------------------"
    echo "[INFO] 停止采集，开始生成结果文件..."

    if [ -n "$(pgrep -P $$ stdbuf)" ]; then
        pkill -P $$ stdbuf 2>/dev/null || true
    fi
    if [ -n "$(pgrep -P $$ cat)" ]; then
        pkill -P $$ cat 2>/dev/null || true
    fi
    echo "[INFO] 后台采集进程已终止"

    echo "[INFO] 最后处理队列中未完成的事件（当前队列长度：${#EVENT_QUEUE[@]}）..."
    process_event_queue

    echo "[INFO] 正在修复JSON格式..."
    ensure_json_complete

    echo -e "\n[SUCCESS] 采集完成！"
    echo "[INFO] → 过滤配置：$( [ "$TARGET_CPU" -eq -1 ] && echo "保留全部CPU" || echo "仅CPU $TARGET_CPU" )"
    echo "[INFO] → 结果文件：$OUTPUT_JSON（可直接用Chrome https://www.ui.perfetto.dev/ 加载）"
    echo "[INFO] → 日志级别：$( [ "$LOG_LEVEL" = "debug" ] && echo "DEBUG" || echo "NORMAL" )"

    if [ -f "$LOCK_FILE" ]; then
        rm -f "$LOCK_FILE"
    fi

    exit 0
}

parse_args "$@"

if [ -f "$LOCK_FILE" ]; then
    echo "[ERROR] 检测到已有采集进程在运行，请先终止进程；若确认无进程运行，可强制删除锁文件："
    echo "  sudo rm -f $LOCK_FILE"
    exit 1
fi
touch "$LOCK_FILE"
trap cleanup SIGINT SIGTERM
check_tracefs_mounted
script_start_ns=$(get_kernel_uptime_ns)
script_start_utc_ms=$(get_current_utc_ms)
script_start_utc_str=$(date -u -d @$((script_start_utc_ms/1000)) +'%Y-%m-%d %H:%M:%S')
echo "[INFO] 脚本启动信息："
echo "[INFO]   - 内核uptime：$script_start_ns ns"
echo "[INFO]   - UTC时间：$script_start_utc_str.$((script_start_utc_ms%1000))（毫秒级）"
echo "[INFO]   - ts基准：事件UTC时间戳（毫秒），与系统时间同步"

safe_write "$TRACEFS/current_tracer" "nop"
safe_write "$TRACEFS/trace" ""
safe_write "$TRACEFS/set_ftrace_pid" ""
safe_write "$TRACEFS/tracing_on" "0"
safe_write "$TRACEFS/events/enable" "0"
safe_write "$TRACEFS/events/sched/$FOCUS_EVENT/enable" "1"
echo "noraw" > "$TRACEFS/trace_options"
safe_write "$TRACEFS/tracing_on" "1"

verify_ftrace_config
start_collection

rm -f "$LOCK_FILE"
