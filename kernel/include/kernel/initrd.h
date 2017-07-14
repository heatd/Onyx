/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _INITRD_H
#define _INITRD_H
#include <stdint.h>
#include <string.h>
#include <kernel/vfs.h>
typedef struct tar_header
{
    	char filename[100];
    	char mode[8];
    	char uid[8];
    	char gid[8];
    	char size[12];
    	char mtime[12];
    	char chksum[8];
    	char typeflag;
}tar_header_t;

#define TAR_TYPE_FILE		'\0'
#define TAR_TYPE_HARD_LNK 	'1'
#define TAR_TYPE_SYMLNK		'2'
#define TAR_TYPE_CHAR_SPECIAL	'3'
#define TAR_TYPE_BLOCK_SPECIAL	'4'
#define TAR_TYPE_DIR		'5'

static inline size_t tar_get_size(const char *in)
{
    	size_t size = 0;
    	unsigned int j;
    	unsigned int count = 1;
    	for (j = 11; j > 0; j--, count *= 8)
		size += ((in[j - 1] - '0') * count);
    	return size;
}
size_t tar_parse(uintptr_t adress);

void init_initrd(void *addr);
int initrd_load_into_ramfs(size_t files);

#endif
