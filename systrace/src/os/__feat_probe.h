/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * sysTrace licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Yang Hanlin
 * Create: 2023-09-18
 * Description: Utility functions for feature probes
 ******************************************************************************/

#ifndef __GOPHER_FEAT_PROBE_H__
#define __GOPHER_FEAT_PROBE_H__

#if defined(BPF_PROG_KERN) || defined(BPF_PROG_USER)
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#endif

#ifdef BPF_PROG_KERN
#include "vmlinux.h"
#elif defined(BPF_PROG_USER)
struct bpf_ringbuf {
};
#endif

#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "common.h"
#endif

/* BPF_MAP_TYPE_RINGBUF original defined in /usr/include/linux/bpf.h, which from kernel-headers
   if BPF_MAP_TYPE_RINGBUF wasn't defined, this kernel does not support using ringbuf */
#ifndef BPF_MAP_TYPE_RINGBUF
#define BPF_MAP_TYPE_RINGBUF    27  // defined here to avoid compile error in lower kernel version
#define IS_RINGBUF_DEFINED      0
#else
#define IS_RINGBUF_DEFINED      1
#endif

#if defined(BPF_PROG_KERN) || defined(BPF_PROG_USER)
static inline char probe_ringbuf()
{
#if CLANG_VER_MAJOR >= 12
    return (char)bpf_core_type_exists(struct bpf_ringbuf);
#else
    return IS_RINGBUF_DEFINED;
#endif
}
#endif
#if !defined(BPF_PROG_KERN) && !defined(BPF_PROG_USER)
static inline bool probe_ringbuf() {
    int map_fd;

    if ((map_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, NULL, 0, 0, getpagesize(), NULL)) < 0) {
        return false;
    }

    close(map_fd);
    return true;
}
#endif

#endif
