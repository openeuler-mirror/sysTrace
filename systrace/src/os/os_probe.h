/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * sysTrace licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: curry
 * Create: 2025-06-20
 * Description: sli probe
 ******************************************************************************/
#ifndef __OS_PROBE_H__
#define __OS_PROBE_H__

#pragma once

#define THREAD_COMM_LEN     16

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
    long long unsigned int start_time;
    long long unsigned int end_time;
    long long unsigned int duration; 
    event_type_e type;
    long long unsigned int delay;
    char comm[THREAD_COMM_LEN];
    char next_comm[THREAD_COMM_LEN];
    long unsigned int next_pid;
} trace_event_data_t;

#endif
