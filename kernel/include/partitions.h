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

typedef int (*fs_handler)(uint64_t sector, int drive, int channel);

fs_handler lookup_handler_from_partition_code(uint8_t part_code);
void part_add_handler(uint8_t part_code, fs_handler handler);
#endif
