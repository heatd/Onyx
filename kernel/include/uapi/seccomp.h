/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_SECCOMP_H
#define _UAPI_SECCOMP_H

#define SECCOMP_MODE_DISABLED 0
#define SECCOMP_MODE_STRICT   1
#define SECCOMP_MODE_FILTER   2

#define SECCOMP_SET_MODE_STRICT  0
#define SECCOMP_SET_MODE_FILTER  1
#define SECCOMP_GET_ACTION_AVAIL 2
#define SECCOMP_GET_NOTIF_SIZES  3

#define SECCOMP_FILTER_FLAG_TSYNC (1U << 0)
#define SECCOMP_FILTER_FLAG_LOG   (1U << 1)

#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#define SECCOMP_RET_KILL_THREAD  0x00000000U
#define SECCOMP_RET_KILL         SECCOMP_RET_KILL_THREAD
#define SECCOMP_RET_TRAP         0x00030000U
#define SECCOMP_RET_ERRNO        0x00050000U
#define SECCOMP_RET_LOG          0x7ffc0000U
#define SECCOMP_RET_ALLOW        0x7fff0000U

#define SECCOMP_RET_ACTION_FULL 0xffff0000U
#define SECCOMP_RET_ACTION      0x7fff0000U
#define SECCOMP_RET_DATA        0x0000ffffU

/* TODO: Unimplemented, fix */

#endif
