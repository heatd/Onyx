/*----------------------------------------------------------------------
 * Copyright (C) 2016 Pedro Falcato
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
/* Definitions of pid_t, uid_t and gid_t, according to the standard */
typedef long pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef long long ssize_t;
typedef long int off_t;
typedef unsigned long int ino_t;
typedef long long blksize_t;
typedef unsigned long fsblkcnt_t;
typedef unsigned long fsfillcnt_t;
typedef long long time_t;
typedef long long clock_t; 
#endif
