/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _TYPES_H
#define _TYPES_H

#include <assert.h>

#ifndef __pid_t_defined
#define __pid_t_defined
typedef long pid_t;
#endif

#ifndef __uid_t_defined
#define __uid_t_defined
typedef unsigned int uid_t;
#endif

#ifndef __gid_t_defined
#define __gid_t_defined
typedef unsigned int gid_t;
#endif

#ifndef __size_t_defined
#define __size_t_defined
#define __need_size_t
#include <stddef.h>
#endif

#ifndef __ssize_t_defined
#define __size_t_defined
typedef long long ssize_t;
#endif

#ifndef __off_t_defined
#define __off_t_defined
typedef long int off_t;
#endif

#ifndef __ino_t_defined
#define __ino_t_defined
typedef unsigned long int ino_t;
#endif

#ifndef __blksize_t_defined
#define __blksize_t_defined
typedef long long blksize_t;
#endif

#ifndef __fsblkcnt_t_defined
#define __fsblkcnt_t_defined
typedef unsigned long fsblkcnt_t;
#endif

#ifndef __fsfillcnt_t_defined
#define __fsfillcnt_t_defined
typedef unsigned long fsfillcnt_t;
#endif

#ifndef __time_t_defined
#define __time_t_defined
typedef long long time_t;
#endif

#ifndef __clock_t_defined
#define __clock_t_defined
typedef long long clock_t;
#endif

#ifndef __id_t_defined
#define __id_t_defined
typedef unsigned long id_t;
#endif

#ifndef __dev_t_defined
#define __dev_t_defined
typedef unsigned int dev_t;
#endif

#if defined(__is_spartix_kernel) && !defined(__uuid_t_defined)
#define __uuid_t_defined
static_assert(sizeof(unsigned short) == 2, "uuid_t needs a 16-bit(2 byte) type!");
typedef unsigned short uuid_t[8];
#endif

#endif