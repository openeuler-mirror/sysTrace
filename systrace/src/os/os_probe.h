/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * sysTrace licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan
 *PSL v2. You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
 *KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
 *NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE. See the
 *Mulan PSL v2 for more details. Author: curry Create: 2025-06-20 Description:
 *sli probe
 ******************************************************************************/
#ifndef __OS_PROBE_H__
#define __OS_PROBE_H__

#pragma once

#define THREAD_COMM_LEN 16
typedef enum {
    OS_PROBE_NONE = 0,
    OS_PROBE_CPU = 1 << 0,
    OS_PROBE_MEM = 1 << 1,
    OS_PROBE_ALL = (OS_PROBE_CPU | OS_PROBE_MEM)
} os_probe_type_e;

typedef enum {
    EVENT_TYPE_MM_FAULT = 0,
    EVENT_TYPE_SWAP_PAGE,
    EVENT_TYPE_COMPACTION,
    EVENT_TYPE_VMSCAN,
    EVENT_TYPE_OFFCPU,
    EVENT_TYPE_MAX
} event_type_e;

typedef struct {
    int key;
    int rank;
    unsigned long long start_time;
    unsigned long long end_time;
    unsigned long long duration;
    event_type_e type;
    unsigned long long delay;
    char comm[THREAD_COMM_LEN];
    char next_comm[THREAD_COMM_LEN];
    int pid;
    int next_pid;
} trace_event_data_t;

#ifdef __cplusplus
extern "C" {
#endif

int os_probe_init(void);
void os_probe_enable_event(os_probe_type_e type);
void os_probe_disable_event(os_probe_type_e type);
void os_probe_exit(void);

#ifdef __cplusplus
}
#endif

#endif