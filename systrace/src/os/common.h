/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * sysTrace licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: Mr.lu
 * Create: 2022-5-30
 * Description: common macro define
 ******************************************************************************/
#ifndef __GOPHER_COMMON_H__
#define __GOPHER_COMMON_H__

#pragma once

#define THOUSAND                1000
#define PATH_NUM                20

#define __maybe_unused      __attribute__((unused))

#define MSEC_PER_SEC    1000L
#define USEC_PER_MSEC   1000L
#define NSEC_PER_USEC   1000L
#define NSEC_PER_MSEC   1000000L
#define USEC_PER_SEC    1000000L
#define NSEC_PER_SEC    1000000000L
#define FSEC_PER_SEC    1000000000000000LL

#ifndef __u8
typedef unsigned char __u8;
typedef __u8 u8;
#endif

#ifndef __s8
typedef signed char __s8;
typedef __s8 s8;
#endif

#ifndef __s16
typedef signed short __s16;
typedef __s16 s16;
#endif

#ifndef __u16
typedef short unsigned int __u16;
typedef __u16 u16;
typedef __u16 __be16;
#endif

#ifndef __u32
typedef unsigned int __u32;
typedef __u32 u32;
typedef __u32 __be32;
typedef __u32 __wsum;
#endif

#ifndef __s64
typedef long long int __s64;
typedef __s64 s64;
#endif

#ifndef __u64
typedef long long unsigned int __u64;
typedef __u64 u64;
#endif
#endif
