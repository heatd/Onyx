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
#ifndef _PARTITIONS_H
#define _PARTITIONS_H

#include <stdint.h>

#include <kernel/block.h>
typedef int (*fs_handler)(uint64_t sector, block_device_t *dev);

enum partition_type_t
{
	PARTITION_TYPE_MBR,
	PARTITION_TYPE_GPT
};
void partition_add_handler(enum partition_type_t part_type, uint8_t part_code, fs_handler handler);
void partition_find_and_mount(enum partition_type_t type, int index, block_device_t *dev);
fs_handler lookup_handler_from_partition_code(enum partition_type_t type, uint8_t part_code);
#endif
