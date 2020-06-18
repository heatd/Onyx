/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <onyx/vfs.h>
#include <onyx/superblock.h>
#include <onyx/atomic.h>

extern "C"
void superblock_init(struct superblock *sb)
{
	INIT_LIST_HEAD(&sb->s_inodes);
	sb->s_ref = 1;
}
