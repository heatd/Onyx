/*
 * Copyright (c) 2023 Pedro Falcato
 * Copyright (c) 2019 Musl libc authors
 *
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _UAPI_WAIT_H
#define _UAPI_WAIT_H

typedef enum
{
    P_ALL = 0,
    P_PID = 1,
    P_PGID = 2
} idtype_t;

#define WNOHANG   1
#define WUNTRACED 2

#define WSTOPPED   2
#define WEXITED    4
#define WCONTINUED 8
#define WNOWAIT    0x1000000

#define __WNOTHREAD 0x20000000
#define __WALL      0x40000000
#define __WCLONE    0x80000000

#define WEXITSTATUS(s)  (((s) &0xff00) >> 8)
#define WTERMSIG(s)     ((s) &0x7f)
#define WSTOPSIG(s)     WEXITSTATUS(s)
#define WCOREDUMP(s)    ((s) &0x80)
#define WIFEXITED(s)    (!WTERMSIG(s))
#define WIFSTOPPED(s)   ((short) ((((s) &0xffff) * 0x10001) >> 8) > 0x7f00)
#define WIFSIGNALED(s)  (((s) &0xffff) - 1U < 0xffu)
#define WIFCONTINUED(s) ((s) == 0xffff)

#endif
