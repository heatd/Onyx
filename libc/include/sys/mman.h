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
#ifndef _MMAN_H
#define _MMAN_H

#include <sys/types.h>

#define PROT_NONE	0x0
#define PROT_READ	0x1
#define PROT_WRITE	0x2
#define PROT_EXEC 	0x4

#define MAP_SHARED	0x0
#define MAP_PRIVATE	0x2
#define MAP_ANONYMOUS	0x4
#define MAP_ANON	MAP_ANONYMOUS
#define MAP_DENYWRITE	0x6
#define MAP_EXECUTABLE	0x8
#define MAP_FILE	0xB
#define MAP_FIXED	0xD
#define MAP_GROWSDOWN	0xF
#define MAP_LOCKED	0x10
#define MAP_NONBLOCK	0x12
#define MAP_NORESERVE	0x14
#define MAP_STACK	0x16
#define MAP_UNINITIALIZED 0x18
#define MAP_FAILED 	(void*) 0x0
void* mmap(void* addr, size_t len,int prot,int flags,int fildes,off_t off);
int munmap(void* addr, size_t len);



#endif
