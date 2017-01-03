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
#ifndef _MBR_H
#define _MBR_H

#include <stdint.h>
typedef struct
{
	uint8_t status;
	uint8_t head;
	uint8_t sect;
	uint8_t cylinder;
	uint8_t part_type;
	uint8_t end_head;
	uint8_t end_sector;
	uint8_t end_cylinder;
	uint32_t sector;
	uint32_t size_sector;
} __attribute__((packed)) mbrpart_t;

void read_partitions();

#endif
