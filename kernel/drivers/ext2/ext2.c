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
#include <kernel/vmm.h>
#include <mbr.h>
#include <partitions.h>
#include <stdio.h>
#include <stdlib.h>
#include <drivers/ext2.h>
#include <kernel/vfs.h>
#include <errno.h>
ext2_fs_t *fslist = NULL;
void *ext2_read_block(uint32_t block_index, uint16_t blocks, ext2_fs_t *fs)
{
	size_t size = blocks * fs->block_size; /* size = nblocks * block size */
	void *buff = vmm_allocate_virt_address(VM_KERNEL, 1, VMM_TYPE_REGULAR, 0); /* Allocate a buffer */
	vmm_map_range(buff, 1, VMM_GLOBAL | VMM_WRITE | VMM_NOEXEC);
	if(!buff)
		return NULL;
	memset(buff, 0, size);
	uint32_t phys = (uint64_t)virtual2phys(buff) >> 0 & 0xFFFFFFFF;
	uint64_t lba = fs->first_sector + (block_index * fs->block_size / 512);
	ata_read_sectors(fs->channel, fs->drive, phys, size, lba);
	return buff;
}
void ext2_write_block(uint32_t block_index, uint16_t blocks, ext2_fs_t *fs, void *buffer)
{
	size_t size = blocks * fs->block_size; /* size = nblocks * block size */
	void *buff = vmm_allocate_virt_address(VM_KERNEL, 1, VMM_TYPE_REGULAR, 0); /* Allocate a buffer */
	vmm_map_range(buff, 1, VMM_GLOBAL | VMM_WRITE | VMM_NOEXEC);
	if(!buff)
		return NULL;
	memcpy(buff, buffer, size);
	uint32_t phys = (uint64_t)virtual2phys(buff) >> 0 & 0xFFFFFFFF;
	uint64_t lba = fs->first_sector + (block_index * fs->block_size / 512);
	ata_read_sectors(fs->channel, fs->drive, phys, size, lba);
	vmm_destroy_mappings(buff, 1);
}
char *ext2_read_inode_bp(inode_t *inode, ext2_fs_t *fs, size_t size_read)
{
	uint64_t size = ((uint64_t)inode->size_hi << 32) | inode->size_lo;
	char *buf = malloc(size);
	memset(buf, 0, size);
	char *put = buf;
	for(uint64_t i = 0; i < size / fs->block_size; i++)
	{
		if(i < 12)
		{
			char *bf = ext2_read_block(inode->dbp[i], 1, fs);
			memcpy(put, bf, fs->block_size);
			size_t pages = fs->block_size / PAGE_SIZE;
			if(fs->block_size % PAGE_SIZE)
				pages++;
			vmm_destroy_mappings(bf, pages);
			put+=fs->block_size;
		}
		if(i >= 12 && i < fs->block_size / 4 + 12)
		{
			uint32_t *indb = ext2_read_block(inode->single_indirect_bp, 1, fs);
			for(uint64_t j = 0; j < fs->block_size / 4; j++)
			{
				if(indb[j] != 0)
				{
					char *bf = ext2_read_block(indb[j], 1, fs);
					memcpy(put, bf, fs->block_size);
					size_t pages = fs->block_size / PAGE_SIZE;
					if(fs->block_size % PAGE_SIZE)
						pages++;
					vmm_destroy_mappings(bf, pages);
					put+=fs->block_size;
					i++;
				}
			}
		}
		if(i >= fs->block_size / 4 + 12 && i < (fs->block_size / 4)*(fs->block_size / 4) + 12)
		{
			uint32_t *dib = ext2_read_block(inode->doubly_indirect_bp, 1, fs);
			for(uint64_t j = 0; j < fs->block_size / 4 ; j++)
			{
				if(dib[j] != 0)
				{
					uint32_t *ib = ext2_read_block(dib[j], 1, fs);
					for(uint64_t k = 0; k < 1024; k++)
					{
						if(ib[k] != 0)
						{
							char *bf = ext2_read_block(ib[j], 1, fs);
							memcpy(put, bf, fs->block_size);
							size_t pages = fs->block_size / PAGE_SIZE;
							if(fs->block_size % PAGE_SIZE)
								pages++;
							vmm_destroy_mappings(bf, pages);
							put+=fs->block_size;
							i++;
						}
					}
				}
			}

		}
		if(i >= (fs->block_size / 4)* (fs->block_size / 4) + 12 && i < (fs->block_size / 4)*(fs->block_size / 4)
		*(fs->block_size / 4) + 12)
		{
			uint32_t *tib = ext2_read_block(inode->trebly_indirect_bp, 1, fs);
			for(uint64_t j = 0; j < fs->block_size/4; j++)
			{
				if(tib[j] != 0)
				{
					uint32_t *dib = ext2_read_block(inode->doubly_indirect_bp, 1, fs);
					for(uint64_t k = 0; k < fs->block_size / 4 ; k++)
					{
						if(dib[k] != 0)
						{
							uint32_t *ib = ext2_read_block(dib[k], 1, fs);
							for(uint64_t l = 0; l < 1024; l++)
							{
								if(ib[l] != 0)
								{
									char *bf = ext2_read_block(ib[l], 1, fs);
									memcpy(put, bf, fs->block_size);
									size_t pages = fs->block_size / PAGE_SIZE;
									if(fs->block_size % PAGE_SIZE)
										pages++;
									vmm_destroy_mappings(bf, pages);
									put+=fs->block_size;
									i++;
								}
							}
						}
					}
				}

			}
		}
	}
	return buf;

}
size_t ext2_read_file(inode_t *inode, ext2_fs_t *fs, size_t sz, uint32_t blck, void *buffer)
{
	uint32_t remainder = sz % fs->block_size;
	uint32_t block_space = sz + fs->block_size - remainder;
	char *buf = malloc(block_space);
	memset(buf, 0, block_space);
	char *put = buf;
	uint32_t block = blck;
	for(uint64_t i = block; i < block_space / fs->block_size; i++)
	{
		if(i < 12)
		{
			char *bf = ext2_read_block(inode->dbp[i], 1, fs);
			memcpy(put, bf, fs->block_size);
			size_t pages = fs->block_size / PAGE_SIZE;
			if(fs->block_size % PAGE_SIZE)
				pages++;
			vmm_destroy_mappings(bf, pages);
			put+=fs->block_size;
		}
		if(i >= 12 && i < fs->block_size / 4 + 12)
		{
			uint32_t *indb = ext2_read_block(inode->single_indirect_bp, 1, fs);
			for(uint64_t j = 0; j < fs->block_size / 4; j++)
			{
				if(indb[j] != 0)
				{
					char *bf = ext2_read_block(indb[j], 1, fs);
					memcpy(put, bf, fs->block_size);
					size_t pages = fs->block_size / PAGE_SIZE;
					if(fs->block_size % PAGE_SIZE)
						pages++;
					vmm_destroy_mappings(bf, pages);
					put+=fs->block_size;
					i++;
				}
			}
		}
		if(i >= fs->block_size / 4 + 12 && i < (fs->block_size / 4)*(fs->block_size / 4) + 12)
		{
			uint32_t *dib = ext2_read_block(inode->doubly_indirect_bp, 1, fs);
			for(uint64_t j = 0; j < fs->block_size / 4 ; j++)
			{
				if(dib[j] != 0)
				{
					uint32_t *ib = ext2_read_block(dib[j], 1, fs);
					for(uint64_t k = 0; k < 1024; k++)
					{
						if(ib[k] != 0)
						{
							char *bf = ext2_read_block(ib[j], 1, fs);
							memcpy(put, bf, fs->block_size);
							size_t pages = fs->block_size / PAGE_SIZE;
							if(fs->block_size % PAGE_SIZE)
								pages++;
							vmm_destroy_mappings(bf, pages);
							put+=fs->block_size;
							i++;
						}
					}
				}
			}

		}
		if(i >= (fs->block_size / 4)* (fs->block_size / 4) + 12 && i < (fs->block_size / 4)*(fs->block_size / 4)
		*(fs->block_size / 4) + 12)
		{
			uint32_t *tib = ext2_read_block(inode->trebly_indirect_bp, 1, fs);
			for(uint64_t j = 0; j < fs->block_size/4; j++)
			{
				if(tib[j] != 0)
				{
					uint32_t *dib = ext2_read_block(inode->doubly_indirect_bp, 1, fs);
					for(uint64_t k = 0; k < fs->block_size / 4 ; k++)
					{
						if(dib[k] != 0)
						{
							uint32_t *ib = ext2_read_block(dib[k], 1, fs);
							for(uint64_t l = 0; l < 1024; l++)
							{
								if(ib[l] != 0)
								{
									char *bf = ext2_read_block(ib[l], 1, fs);
									memcpy(put, bf, fs->block_size);
									size_t pages = fs->block_size / PAGE_SIZE;
									if(fs->block_size % PAGE_SIZE)
										pages++;
									vmm_destroy_mappings(bf, pages);
									put+=fs->block_size;
									i++;
								}
							}
						}
					}
				}

			}
		}
	}
	memcpy(buffer, buf, sz);
	free(buf);
	return sz;
}
size_t ext2_write_file(inode_t *inode, ext2_fs_t *fs, size_t sz, uint32_t blck, void *buffer)
{
	uint32_t remainder = sz % fs->block_size;
	uint32_t block_space = sz + fs->block_size - remainder;
	char *put = buffer;
	uint32_t block = blck;
	for(uint64_t i = block; i < block_space / fs->block_size; i++)
	{
		if(i < 12)
		{
			ext2_write_block(inode->dbp[i], 1, fs, put);
			put+=fs->block_size;
		}
		if(i >= 12 && i < fs->block_size / 4 + 12)
		{
			uint32_t *indb = ext2_read_block(inode->single_indirect_bp, 1, fs);
			for(uint64_t j = 0; j < fs->block_size / 4; j++)
			{
				if(indb[j] != 0)
				{
					ext2_write_block(indb[j], 1, fs, put);
					put+=fs->block_size;
					i++;
				}
			}
		}
		if(i >= fs->block_size / 4 + 12 && i < (fs->block_size / 4)*(fs->block_size / 4) + 12)
		{
			uint32_t *dib = ext2_read_block(inode->doubly_indirect_bp, 1, fs);
			for(uint64_t j = 0; j < fs->block_size / 4 ; j++)
			{
				if(dib[j] != 0)
				{
					uint32_t *ib = ext2_read_block(dib[j], 1, fs);
					for(uint64_t k = 0; k < 1024; k++)
					{
						if(ib[k] != 0)
						{
							ext2_write_block(ib[k], 1, fs, put);
							put+=fs->block_size;
							i++;
						}
					}
				}
			}

		}
		if(i >= (fs->block_size / 4)* (fs->block_size / 4) + 12 && i < (fs->block_size / 4)*(fs->block_size / 4)
		*(fs->block_size / 4) + 12)
		{
			uint32_t *tib = ext2_read_block(inode->trebly_indirect_bp, 1, fs);
			for(uint64_t j = 0; j < fs->block_size/4; j++)
			{
				if(tib[j] != 0)
				{
					uint32_t *dib = ext2_read_block(inode->doubly_indirect_bp, 1, fs);
					for(uint64_t k = 0; k < fs->block_size / 4 ; k++)
					{
						if(dib[k] != 0)
						{
							uint32_t *ib = ext2_read_block(dib[k], 1, fs);
							for(uint64_t l = 0; l < 1024; l++)
							{
								if(ib[l] != 0)
								{
									ext2_write_block(ib[l], 1, fs, put);
									put += fs->block_size;
									i++;
								}
							}
						}
					}
				}

			}
		}
	}
	return sz;
}
inode_t *ext2_get_inode_from_number(ext2_fs_t *fs, uint32_t inode)
{
	uint32_t block_size = fs->block_size;
	uint32_t bg = (inode - 1) / fs->inodes_per_block_group;
	uint32_t index = (inode - 1) % fs->inodes_per_block_group;
	uint32_t block = (index * fs->inode_size) / block_size;
	uint32_t blockind = (index * fs->inode_size) % block_size;
	block_group_desc_t *bgd = &fs->bgdt[bg];
	inode_t *inode_block = (inode_t*)((char *)ext2_read_block(bgd->inode_table_addr + block, 1, fs) + blockind);

	return inode_block;
}
inode_t *ext2_get_inode_from_dir(ext2_fs_t *fs, dir_entry_t *dirent, char *name, uint32_t *inode_number)
{
	dir_entry_t *dirs = dirent;
	while(dirs->inode != 0)
	{
		if(!strcmp(dirs->name, name))
		{
			*inode_number = dirs->inode;
			return ext2_get_inode_from_number(fs,dirs->inode);
		}
		dirs = (dir_entry_t*)((char*)dirs + dirs->size);
	}
	return NULL;
}
size_t ext2_write(size_t offset, size_t sizeofwrite, void *buffer, vfsnode_t *node)
{
	ext2_fs_t *fs = fslist;
	printf("ay\n");
	uint32_t block_index = offset / fs->block_size;
	if(offset % fs->block_size)
		block_index--;
	printf("hey");
	inode_t *ino = ext2_get_inode_from_number(fs, node->inode);
	if(!ino)
		return errno = EINVAL, (size_t)-1;
	/* Ok, this one will be tricky. I'll need to handle 3 different cases of writing. 
	 * 1 - Overwriting file data - this one is easy. Just get the block offset and write to it, then write to disk again again
	 * 2 - We're writing to a block that's already allocated to the inode, and zeroed - this is also easy, just write to it
	 * 3 - We're writing to a new block - this one is the hardest. We'll need to allocate a new block, and add it to the disk inode
	 * this one will require many more writes and reads than usual.
	*/
	if(offset < node->size)
	{
		// This is case 1 of ext2_write
		char *buf = malloc(sizeofwrite);
		if(!buf)
			return errno = ENOMEM, -1;
		printf("Block index: %u\nSize of write: %u\n", block_index, sizeofwrite);
		size_t read = ext2_read_file(ino, fs, sizeofwrite, block_index, buf);
		if(read == (size_t)-1)
			return errno = EIO, -1;
		memcpy(buf + (offset % fs->block_size), buffer, sizeofwrite);
		printf("Writing!\n");
		return ext2_write_file(ino, fs, sizeofwrite, block_index, buf);
	}
	return errno = ENOSYS, -1;

}
size_t ext2_read(size_t offset, size_t sizeofreading, void *buffer, vfsnode_t *nd)
{
	if(offset > nd->size)
		return errno = EINVAL, -1;
	ext2_fs_t *fs = fslist;
	uint32_t block_index = offset/fs->block_size;
	if(offset % fs->block_size)
		block_index++;
	inode_t *ino = ext2_get_inode_from_number(fs, nd->inode);
	if(!ino)
		return errno = EINVAL;
	size_t size = ext2_read_file(ino, fs, sizeofreading, block_index, buffer);
	return size;
}
vfsnode_t *ext2_open(vfsnode_t *nd, const char *name)
{
	uint32_t inoden = nd->inode;
	ext2_fs_t *fs = fslist;
	uint32_t inode_num;
	// Get the inode structure from the number
	inode_t *ino = ext2_get_inode_from_number(fs, inoden);
	// Calculate the size of the directory
	size_t size = ((uint64_t)ino->size_hi << 32) | ino->size_lo;
	char *p = name;
	char *inode_data = ext2_read_inode_bp(ino, fs, &size);
	dir_entry_t *dir = (dir_entry_t*)inode_data;
	while(p)
	{
		if(p != name)
			p++;
		// Count the size needed to contain the name
		size_t len = 0;
		while(p[len] != '\0' && p[len] != '/')
		{
			len++;
		}
		char *path = malloc(len+2);
		if(!path)
			return errno = ENOMEM, NULL;
		memset(path, 0, len); // This memset is just to make sure the string is zero-terminated
		memcpy(path, p, len);
		ino = ext2_get_inode_from_dir(fs, dir, path, &inode_num);
		if(strtok(p, "/") == NULL)
			break;
		inode_data = ext2_read_inode_bp(ino, fs, &size);
		dir = (dir_entry_t*)inode_data;
		p = strtok(p, "/");
		free(path);
	}
	vfsnode_t *node = malloc(sizeof(vfsnode_t));
	memset(node, 0, sizeof(vfsnode_t));
	node->name = (char*)name;
	node->inode = inode_num;
	node->read = ext2_read;
	node->open = ext2_open;
	node->write = ext2_write;
	node->size = ((uint64_t)ino->size_hi << 32) | ino->size_lo;
	node->uid = ino->uid;
	node->gid = ino->gid;
	return node;
}
int ext2_open_partition(uint64_t sector, int drive, int channel)
{
	printf("Handling ext2 partition at sector %d\n", sector);
	superblock_t *sb = vmm_allocate_virt_address(VM_KERNEL, 1/*64K*/, VMM_TYPE_REGULAR, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	vmm_map_range(sb, 1, VMM_WRITE | VMM_NOEXEC | VMM_GLOBAL);
	uint32_t phys = (uint64_t)virtual2phys(sb) >> 0;
	uint64_t lba = sector + 2;
	ata_read_sectors(channel, drive, phys, 1024, lba);
	if(sb->ext2sig == 0xef53)
		printf("Valid ext2 signature detected!\n");
	else
	{
		printf("ERROR: Invalid ext2 signature %x\n", sb->ext2sig);
		return 1;
	}
	ext2_fs_t *fs = malloc(sizeof(ext2_fs_t));
	if(!fslist) fslist = fs;
	else
	{
		ext2_fs_t *s = fslist;
		while(s->next)
		{
			s = s->next;
		}
		s->next = fs;
	}
	// good til here
	fs->drive = drive;
	fs->channel = channel;
	fs->sb = sb;
	fs->major = sb->major_version;
	fs->minor = sb->minor_version;
	fs->first_sector = sector;
	fs->total_inodes = sb->total_inodes;
	fs->total_blocks = sb->total_blocks;
	fs->block_size = 1024 << sb->log2blocksz;
	fs->frag_size = 1024 << sb->log2fragsz;
	fs->inode_size = sb->size_inode_bytes;
	fs->blocks_per_block_group = sb->blockgroupblocks;
	fs->inodes_per_block_group = sb->blockgroupinodes;
	fs->number_of_block_groups = fs->total_blocks / fs->blocks_per_block_group;
	if (fs->total_blocks % fs->blocks_per_block_group)
		fs->number_of_block_groups++;
	block_group_desc_t *bgdt = NULL;
	size_t blocks_for_bgdt = (fs->number_of_block_groups * sizeof(block_group_desc_t)) / fs->block_size;
	if((fs->number_of_block_groups * sizeof(block_group_desc_t)) % fs->block_size)
		blocks_for_bgdt++;
	if(fs->block_size == 1024)
		bgdt = ext2_read_block(2, (uint16_t)blocks_for_bgdt, fs);
	else
		bgdt = ext2_read_block(1, (uint16_t)blocks_for_bgdt, fs);
	fs->bgdt = bgdt;
	vfsnode_t *node = malloc(sizeof(vfsnode_t));
	node->name = "";
	node->inode = 2;
	node->open = ext2_open;
	node->read = ext2_read;
	mount_fs(node, "/");
	return 0;
}
void init_ext2drv()
{
	part_add_handler(EXT2_MBR_CODE, ext2_open_partition);
}
