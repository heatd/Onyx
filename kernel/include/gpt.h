/*----------------------------------------------------------------------
 * Copyright (C) 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#ifndef _GPT_H
#define _GPT_H

#include <stdint.h>

#include <sys/types.h>

#define GPT_SIGNATURE	"EFI PART"
typedef struct
{
	char signature[8]; /* EFI PART */
	uint32_t rev;
	uint32_t header_size;
	uint32_t crc32_checksum;
	uint32_t res;
	uint64_t current_lba;
	uint64_t backup_lba;
	uint64_t first_lba;
	uint64_t last_lba;
	uuid_t disk_uuid;
	uint64_t partition_entries_lba;
	uint32_t num_partitions;
	uint32_t part_entry_len;
	uint32_t partition_array_crc32;
} gpt_header_t;

typedef struct
{
	uuid_t partition_type;
	uuid_t partition_uuid;
	uint64_t first_lba;
	uint64_t last_lba;
	uint64_t attrb_flags;
	uint16_t partition_name[36];
} gpt_partition_entry_t;
#endif