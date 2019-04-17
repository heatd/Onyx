/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdio.h>

#include "vbt.h"

#include "igpu_drv.h"

int igd_is_valid_vbt(struct igpu_device *dev, struct vbt_header *header)
{

	if(memcmp(&header->signature, VBT_SIGNATURE_START,
		  VBT_SIGNATURE_START_LEN))
	{
		printk("igd: vbt bad signature\n");
		return -1;
	}

	if(header->header_size < sizeof(struct vbt_header))
	{
		printk("igd: vbt bad header size\n");
		return -1;
	}

	if(header->bdb_off > header->vbt_size)
	{
		printk("igd: vbt bad bdb off\n");
		return -1;
	}

	struct bdb_header *bdb = (void *) ((char *) header + header->bdb_off);
	
	if(bdb->header_size < sizeof(struct bdb_header))
	{
		printk("igd: vbt bad bdb header size\n");
		return -1;
	}

	if(memcmp(&bdb->signature, BDB_SIGNATURE, BDB_SIGNATURE_LEN))
	{
		printk("igd: vbt bad bdb signature %.16s.\n", bdb->signature);
		return -1;
	}

	printk("igd: Found valid VBT with signature %.16s\n", header->signature);

	dev->igd_vbt = header;

	return 0;
}


uint32_t get_blk_size(struct bdb_block_header *blk)
{
	if(blk->block_id == BDB_MIPI_SEQUENCE)
	{
		/* Check the revision for 3+ */
		unsigned char revision = blk->data[0];
		if(revision >= 3)
		{
			uint32_t *ptr = &blk->data[1];
			return *ptr;
		}
	}

	return blk->block_size;
}

struct bdb_block_header *igd_find_bdb_block(struct bdb_header *bdb,
					    unsigned char id)
{
	uint16_t size = bdb->bdb_size;
	uint32_t pointer = bdb->header_size;

	while(pointer + sizeof(struct bdb_block_header) < size)
	{
		struct bdb_block_header *blk = (void *) ((uint8_t *) bdb + pointer);
		if(blk->block_id == id)
			return blk;

		pointer += get_blk_size(blk);
	} 
}

int igd_parse_vbt(struct igpu_device *dev)
{
	return 0;
}