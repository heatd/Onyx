/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <kernel/initrd.h>
#include <kernel/vfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <kernel/panic.h>
#include <kernel/dev.h>
#include <assert.h>
#include <math.h>
tar_header_t *headers[300] = { 0 };
size_t n_files = 0;
size_t tar_parse(uintptr_t address)
{
	size_t i = 0;

	for (i = 0;; i++) {
		tar_header_t *header = (tar_header_t *) address;
		if (header->filename[0] == '\0')
			break;
		/* Remove the trailing slash */
		if(header->filename[strlen(header->filename)-1] == '/')
			header->filename[strlen(header->filename)-1] = 0;
		size_t size = tar_get_size(header->size);
		headers[i] = header;
		address += ((size / 512) + 1) * 512;
		if (size % 512)
			address += 512;
	}
	return i;
}
size_t tar_read(int flags, size_t offset, size_t sizeofreading, void *buffer, vfsnode_t *this)
{
	(void) flags;
	if(offset > this->size)
		return 0;
	size_t to_be_read = offset + sizeofreading > this->size ? sizeofreading - offset - sizeofreading + this->size : sizeofreading;
	char *temp_buffer = (char *) headers[this->inode] + 512 + offset;
	memcpy(buffer, temp_buffer, to_be_read);
	return to_be_read;
}

size_t tar_write(size_t offset, size_t sizeOfWriting, void *buffer, vfsnode_t *this)
{
	(void) offset;
	(void) sizeOfWriting;
	(void) buffer;
	(void) this;
	/* You can not write to a tar file (usually results in corruption) */
	return errno = EROFS, 0;
}
void tar_close(vfsnode_t *this)
{
	(void) this;
	return;
}
int tar_stat(struct stat *buf, struct vfsnode *node)
{
	buf->st_dev = node->dev;
	buf->st_ino = node->inode;
	buf->st_uid = node->uid;
	buf->st_gid = node->gid;
	buf->st_size = node->size;

	return 0;
}
unsigned int tar_getdents(unsigned int count, struct dirent* dirp, off_t off, vfsnode_t* this)
{
	char *full_path = this->name;
	tar_header_t **iterator = headers;
	unsigned int found = 0;
	for(size_t i = 0; i < n_files; i++)
	{
		if(!strcmp(iterator[i]->filename, full_path))
			continue;
		if(!memcmp(iterator[i]->filename, full_path, strlen(full_path)))
		{
			/* The memcmp above was just a primitive search, this is the real parsing
			   Basically the code after this parses the string using strtok(3) and tries to figure out if it's
			   a direct child of the directory, etc.
			   Note that some parts of the code are specific to tarfs(that's why it's under 'initrd.c')
			*/
			char *l = iterator[i]->filename, *temp = NULL, *before = l;
			l = strtok(l, "/");
			while((temp = strtok(NULL, "/")))
			{
				if(*temp == '/' && temp[1] == '\0')
					break;
				before = l;
				l = temp;	
			}
			/* If the token before the last / isn't equal to the last bytes of the full_path, it's not a 
			   direct child 
			*/
			char *last_tok = full_path+(strlen(full_path) - (size_t) (l+1 - before));
			if(memcmp(before, last_tok, (size_t) (l+1 - before)))
				continue;
			l++;
			dirp[found].d_ino = i;
			strcpy(dirp[found].d_name, l);
			
			/* Fix trailing slashes (TAR specific) */
			if(dirp[found].d_name[strlen(dirp[found].d_name)-1] == '/')
				dirp[found].d_name[strlen(dirp[found].d_name)-1] = '\0';
			if(iterator[i]->typeflag == TAR_TYPE_DIR)
				dirp[found].d_type = DT_DIR;
			else if(iterator[i]->typeflag == TAR_TYPE_FILE)
				dirp[found].d_type = DT_REG;
			else if(iterator[i]->typeflag == TAR_TYPE_CHAR_SPECIAL)
				dirp[found].d_type = DT_CHR;
			else if(iterator[i]->typeflag == TAR_TYPE_BLOCK_SPECIAL)
				dirp[found].d_type = DT_BLK;
			else if(iterator[i]->typeflag == TAR_TYPE_HARD_LNK || iterator[i]->typeflag == TAR_TYPE_SYMLNK)
				dirp[found].d_type = DT_LNK;
			else
				dirp[found].d_type = DT_UNKNOWN;
			found++;
			count--;
		}
		if(count == 0)
			break;
	}
	return found;
}
char *get_complete_tar_path(vfsnode_t *node, const char *name)
{
	size_t sizebuf = strlen("sysroot") + strlen(node->name) + strlen(name) + 3;
	char *buffer = malloc(sizebuf);
	if(!buffer)
		return NULL;
	memset(buffer, 0, sizebuf);
	strcpy(buffer, "sysroot");
	if(strlen(node->name) != 1) strcat(buffer, node->name);
	if(name[0] != '/')	strcat(buffer, "/");
	strcat(buffer, name);
	return buffer;
}
vfsnode_t *tar_open(vfsnode_t *this, const char *name)
{
	char *full_path = get_complete_tar_path(this, name);
	if(!full_path)
		return errno = ENOMEM, NULL;
	tar_header_t **iterator = headers;
	for(size_t i = 0; i < n_files; i++)
	{
		if(!strcmp(iterator[i]->filename, full_path))
		{
			// This part of the code seems broken, needs to be looked at
			vfsnode_t *node = malloc(sizeof(vfsnode_t));
			if(!node)
			{
				free(full_path);
				return errno = ENOMEM, NULL;
			}
			memset(node, 0, sizeof(*node));
			node->name = malloc(strlen(this->name) + strlen(name) + 3);
			if(!node->name)
			{
				free(full_path);
				free(node);
				return errno = ENOMEM, NULL;
			}
			memset(node->name, 0, strlen(this->name) + strlen(name) + 3);
			strcpy(node->name, this->name);
			if(node->name[strlen(node->name) - 1] != '/') node->name[strlen(node->name)] = '/';
			strcpy(node->name + strlen(node->name), name);
			node->dev = this->dev;
			node->inode = i;
			node->size = tar_get_size(iterator[i]->size);
			if(iterator[i]->typeflag == TAR_TYPE_DIR)
				node->type = VFS_TYPE_DIR;
			else
				node->type = VFS_TYPE_FILE;
			free(full_path);
			return node;
		}
	}
	free(full_path);
	return errno = ENOENT, NULL;
}
void init_initrd(void *initrd)
{
	printf("Found an Initrd at %p\n", initrd);
	n_files = tar_parse((uintptr_t) initrd);
	printf("Found %d files in the Initrd\n", n_files);
	vfsnode_t *node = malloc(sizeof(vfsnode_t));
	if(!node)
	{
		panic("initrd: out of memory\n");
	}
	memset(node, 0, sizeof(vfsnode_t));
	node->name = "/";
	struct minor_device *min_dev = dev_register(0, 0);
	if(!min_dev)
		panic("Could not allocate a device id!\n");
	
	min_dev->fops = malloc(sizeof(struct file_ops));
	if(!min_dev->fops)
		panic("Could not allocate a file operation table!\n");
	memset(min_dev->fops, 0, sizeof(struct file_ops));

	min_dev->fops->open = tar_open;
	min_dev->fops->close = tar_close;
	min_dev->fops->read = tar_read;
	min_dev->fops->write = tar_write;
	min_dev->fops->getdents = tar_getdents;
	min_dev->fops->stat = tar_stat;

	node->dev = min_dev->majorminor;

	node->type = VFS_TYPE_DIR;
	node->inode = 0;
	mount_fs(node, "/");
	printf("Mounted initrd on /\n");
}
