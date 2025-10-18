import json

from matplotlib import gridspec
from matplotlib.table import Table
import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
import os
from scipy import stats
import math


event_type_dic = {
    0: "mm_fault",
    1: "swap_page",
    2: "compaction",
    3: "vmscan",
    4: "offcpu",
    5: "unknown"
}

plt.rcParams["axes.unicode_minus"] = False 


def calculate_statistics(data):
    """计算一组数据的各种统计指标"""
    if not data:
        return None

    arr = np.array(data, dtype=np.float64)

    count = len(arr)
    mean = np.mean(arr)
    var = np.var(arr)
    median = np.median(arr)
    max_val = np.max(arr)
    min_val = np.min(arr)


    mode_result = stats.mode(arr, keepdims=True)
    mode = mode_result.mode[0]
    mode_count = mode_result.count[0]

    percentiles = np.percentile(arr, [25, 75, 90, 95])
    p25, p75, p90, p95 = percentiles

    if count > 1:
        arr_without_max = arr[arr != max_val]
        var_without_max = np.mean(arr_without_max) if len(arr_without_max) > 0 else 0.0
    else:
        var_without_max = 0.0

    return {
        "count": int(count),
        "mean": float(mean),
        "variance": float(var),
        "median": float(median),
        "mode": {
            "value": float(mode),
            "count": int(mode_count)
        },
        "mean_without_max": float(var_without_max),
        "max": float(max_val),
        "min": float(min_val),
        "percentile_25": float(p25),
        "percentile_75": float(p75),
        "percentile_90": float(p90),
        "percentile_95": float(p95)
    }


def analyze_os_json(input_file, output_json):
    """分析os.json文件并按事件类型分组"""
    with open(input_file, 'r') as f:
        data = json.load(f)

    process_event_types = defaultdict(lambda: defaultdict(list))  
    all_events = sorted(data['traceEvents'], key=lambda x: x['ts'])

    for event in all_events:
        pid = event['pid']
        event_type = event['name']
        process_event_types[pid][event_type].append(event)

    event_type_count = defaultdict(int)
    for pid_events in process_event_types.values():
        for event_type, events in pid_events.items():
            event_type_count[event_type] += len(events)

    for event_type, count in event_type_count.items():
        print(f"  {event_type}: {count}个事件")

    statistics = defaultdict(lambda: defaultdict(dict))
    for pid, event_types in process_event_types.items():
        for event_type, events in event_types.items():
            durations = [event['dur'] for event in events]
            stats = calculate_statistics(durations)
            if stats:
                statistics[pid][event_type] = stats

    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(statistics, f, ensure_ascii=False, indent=2)

    print(f"统计数据已保存到 {output_json}")
    return process_event_types


def analyze_sus_comm_stats(input_file, result_name, output_dir='sus_comm_pro'):
    """
    分析os.json文件中不同进程中按sus_comm分类的线程统计信息
    统计指标：数量、总持续时间、最小持续时间、最大持续时间
    """
    with open(input_file, 'r') as f:
        data = json.load(f)

    process_suscomm_stats = defaultdict(
        lambda: defaultdict(
            lambda: {'count': 0, 'total_duration': 0.0, 'min_duration': float('inf'), 'max_duration': 0.0}
        )
    )

    for event in data['traceEvents']:
        if 'dur' not in event:
            continue

        pid = event.get('pid', 'Unknown')

        args = event.get('args', {})
        sus_comm = args.get('sus_comm', 'Unknown')
        duration = event['dur']

        stats = process_suscomm_stats[pid][sus_comm]
        stats['count'] += 1
        stats['total_duration'] += duration
        if duration < stats['min_duration']:
            stats['min_duration'] = duration
        if duration > stats['max_duration']:
            stats['max_duration'] = duration

    os.makedirs(output_dir, exist_ok=True)
    sorted_pids = sorted(process_suscomm_stats.keys(), key=lambda x: str(x))
    total_rows = 0
    table_data_list = []

    for pid in sorted_pids:
        suscomms = process_suscomm_stats[pid]
        sorted_suscomms = sorted(suscomms.keys())
        table_data = []

        for comm in sorted_suscomms:
            stats = suscomms[comm]
            min_dur = f"{stats['min_duration']:.2f}" if stats['min_duration'] != float('inf') else "0.00"
            table_data.append([
                comm,  
                str(stats['count']),  
                f"{stats['total_duration']:.2f}", 
                min_dur,  
                f"{stats['max_duration']:.2f}"  
            ])

        table_data_list.append((pid, table_data, sorted_suscomms))
        total_rows += len(sorted_suscomms) + 1

    if total_rows == 0:
        print("没有找到有效的线程事件数据。")
        return

    fig = plt.figure(figsize=(14, total_rows * 0.4 + len(sorted_pids) * 0.4))
    ax = plt.gca()
    ax.axis('off')
    gs = gridspec.GridSpec(len(sorted_pids), 2, width_ratios=[1, 12])

    current_index = 0
    for pid, table_data, sorted_suscomms in table_data_list:
        if not table_data:
            continue

        title_ax = fig.add_subplot(gs[current_index, 0])
        title_ax.axis('off')
        title_ax.text(
            0.5, 0.5, f'进程 PID: {pid}',
            fontsize=10, fontweight='bold',
            rotation=90, ha='center', va='center'
        )

        table_ax = fig.add_subplot(gs[current_index, 1])
        table_ax.axis('off')
        column_labels = ["sus_comm", "事件数量", "总持续时间", "最小持续时间", "最大持续时间"]
        row_labels = [str(i + 1) for i in range(len(table_data))]

        table = table_ax.table(
            cellText=table_data,
            rowLabels=row_labels,
            colLabels=column_labels,
            cellLoc='center',
            loc='upper left',
            bbox=[0, 0, 1, 1]  
        )

        table.auto_set_font_size(False)
        table.set_fontsize(8)
        table.scale(1.1, 1.2)  
        header_color = '#4F81BD'
        for i in range(len(column_labels)):
            table[(0, i)].set_facecolor(header_color)
            table[(0, i)].set_text_props(weight='bold', color='white')

        current_index += 1

    plt.tight_layout(pad=1.2)
    output_file = os.path.join(output_dir, f"process_suscomm_analysis_{result_name}.png")
    plt.savefig(output_file, bbox_inches='tight', dpi=300)
    plt.close()

    print(f"分析结果已保存至: {output_file}")
    print(f"结果目录: {output_dir}")


def generate_plots(process_event_types, result_name, output_dir='plots', num_bins=10):
    """为每种事件类型生成一个图，包含所有进程的该事件直方图作为子图
    重点展示阈值以内的数据分布，阈值以外的数据合并为一个柱，同时生成信息熵表格"""
    os.makedirs(output_dir, exist_ok=True)

    event_type_processes = defaultdict(dict)  
    for pid, event_types in process_event_types.items():
        for event_type, events in event_types.items():
            durations = [event['dur'] for event in events]
            event_type_processes[event_type][pid] = durations

    for event_type, pid_durations in event_type_processes.items():
        num_processes = len(pid_durations)
        entropy_data = []

        rows = int(np.ceil(np.sqrt(num_processes)))
        cols = int(np.ceil(num_processes / rows))

        fig, axes = plt.subplots(rows, cols, figsize=(5 * cols, 4 * rows))
        fig.suptitle(f'{event_type}_{result_name} latency compare per rank', fontsize=16, y=1.02)

        if num_processes == 1:
            axes = np.array([axes])

        for i, (pid, durations) in enumerate(pid_durations.items()):
            ax = axes.flat[i]
            d_count = len(durations)

            if durations:  
                median = np.median(durations)
                threshold = 2 * median

                above_threshold_count = sum(1 for d in durations if d > threshold)
                bins = np.linspace(0, threshold, num_bins + 1) 
                within_threshold = [d for d in durations if d <= threshold]
                n, bins, patches = ax.hist(within_threshold, bins=bins, alpha=0.7,
                                           color='blue', edgecolor='black')
                pro = n / d_count
                pro = np.append(pro, above_threshold_count / d_count)

                entropy = 0
                for p in pro:
                    if p > 0:
                        entropy -= p * math.log2(p)

                entropy_data.append((pid, d_count, entropy))
                if above_threshold_count > 0:
                    ax.bar(bins[-1] + (bins[1] - bins[0]) / 2, above_threshold_count,
                           width=(bins[1] - bins[0]), color='red', alpha=0.7,
                           edgecolor='black', label=f'>{threshold:.2f} ({above_threshold_count}个)')
            else:
                median = 0
                threshold = 0
                entropy = 0
                entropy_data.append((pid, 0, 0))

            ax.set_xlabel('event_time(ms)', fontsize=8)
            ax.set_ylabel('event_count', fontsize=8)
            ax.set_title(f'Process {pid}\n cross_entroy: {entropy:.4f}', fontsize=10)
            ax.grid(True, linestyle='--', alpha=0.7)
            ax.axvline(x=median, color='r', linestyle='--', alpha=0.5, label=f'median: {median:.2f}')

            ax.legend(fontsize=6)
            ax.tick_params(axis='both', which='major', labelsize=7)

        for i in range(num_processes, rows * cols):
            axes.flat[i].axis('off')

        plt.tight_layout()

        safe_event_type = event_type.replace(':', '_').replace(' ', '_')
        output_path = os.path.join(output_dir, f'{safe_event_type}_process_comparison_{result_name}.png')
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"{event_type} compare per rank {output_path}")

        if entropy_data:
            create_entropy_table(entropy_data, event_type, result_name, output_dir, safe_event_type)


def create_entropy_table(entropy_data, event_type, result_name, output_dir, safe_event_type):
    """创建并保存信息熵表格图片"""
    entropy_data.sort(key=lambda x: x[0])

    fig, ax = plt.subplots(figsize=(8, 0.5 + 0.3 * len(entropy_data)))  
    ax.axis('off') 

    table = Table(ax, bbox=[0, 0, 1, 1])

    cell_width = 1.0 / 3  
    cell_height = 0.8 / len(entropy_data) if entropy_data else 0.8

    table.auto_set_font_size(False)
    table.set_fontsize(12)
    table.add_cell(0, 0, cell_width, cell_height, text='rank', loc='center', facecolor='#f0f0f0')
    table.add_cell(0, 1, cell_width, cell_height, text='event_count', loc='center', facecolor='#f0f0f0')
    table.add_cell(0, 2, cell_width, cell_height, text='cross_entropy', loc='center', facecolor='#f0f0f0')

    for row, (pid, count, entropy) in enumerate(entropy_data, start=1):
        table.add_cell(row, 0, cell_width, cell_height, text=str(pid), loc='center')
        table.add_cell(row, 1, cell_width, cell_height, text=str(count), loc='center')
        table.add_cell(row, 2, cell_width, cell_height, text=f'{entropy:.4f}', loc='center')

    ax.add_table(table)

    plt.title(f'{event_type}_{result_name} cross_entroy per rank ', fontsize=14, pad=20)

    table_output_path = os.path.join(output_dir, f'{safe_event_type}_entropy_table_{result_name}.png')
    plt.savefig(table_output_path, dpi=300, bbox_inches='tight')
    plt.close()

    print(f"{event_type} cross-entroy saved to {table_output_path}")


def main():
    input_json = './newddr.json'
    output_json = 'distribution_statistics_mmfault.json'
    file_name = input_json.split('\\')[-1]
    result_name = file_name.split('.')[0]

    if not os.path.exists(input_json):
        print(f"error： cant not find input file: {input_json}")
        return

    process_event_types = analyze_os_json(input_json, output_json)
    # analyze_sus_comm_stats(input_json,result_name)
    generate_plots(process_event_types,result_name,num_bins=10)


if __name__ == "__main__":
    main()
