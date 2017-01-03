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
#ifndef _DIRENT_H
#define _DIRENT_H
#include <sys/cdefs.h>
#include <sys/types.h>

struct dirent
{
    	ino_t d_ino;
	off_t d_off;
	unsigned short d_reclen;
	unsigned char  d_type;
	char d_name[256];
};
enum
{
	DT_UNKNOWN = 0,
#define DT_UNKNOWN	DT_UNKNOWN
	DT_FIFO = 1,
#define DT_FIFO		DT_FIFO
	DT_CHR = 2,
#define DT_CHR		DT_CHR
	DT_DIR = 4,
#define DT_DIR		DT_DIR
	DT_BLK = 6,
#define DT_BLK		DT_BLK
	DT_REG = 8,
#define DT_REG		DT_REG
	DT_LNK = 10,
#define DT_LNK		DT_LNK
	DT_SOCK = 12,
#define DT_SOCK		DT_SOCK
	DT_WHT = 14
#define DT_WHT		DT_WHT
};
#endif
