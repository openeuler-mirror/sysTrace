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
 * Description: bpf header
 ******************************************************************************/
#ifndef __GOPHER_BPF_H__
#define __GOPHER_BPF_H__

#pragma once

#include "common.h"

#define LIBBPF_VERSION(a, b) (((a) << 8) + (b))
#define CURRENT_LIBBPF_VERSION LIBBPF_VERSION(LIBBPF_VER_MAJOR, LIBBPF_VER_MINOR)

#include "__libbpf.h"
#include "__bpf_kern.h"
#include "__feat_probe.h"
#include "__compat.h"

#endif
