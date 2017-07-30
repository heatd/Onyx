/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
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

#ifdef __cplusplus
extern "C"{
#endif

void read_partitions(void);

#ifdef __cplusplus
}
#endif
#endif
