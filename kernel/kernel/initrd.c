/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <math.h>

#include <onyx/panic.h>
#include <onyx/dev.h>
#include <onyx/tmpfs.h>
#include <onyx/initrd.h>
#include <onyx/vfs.h>

#include <libgen.h>

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
size_t tar_read(int flags, size_t offset, size_t sizeofreading, void *buffer, struct inode *this)
{
	(void) flags;
	if(offset > this->size)
		return 0;
	size_t to_be_read = offset + sizeofreading > this->size ? sizeofreading - offset - sizeofreading + this->size : sizeofreading;
	char *temp_buffer = (char *) headers[this->inode] + 512 + offset;
	memcpy(buffer, temp_buffer, to_be_read);
	return to_be_read;
}

size_t tar_write(size_t offset, size_t sizeOfWriting, void *buffer, struct inode *this)
{
	(void) offset;
	(void) sizeOfWriting;
	(void) buffer;
	(void) this;
	/* You can not write to a tar file (usually results in corruption) */
	return errno = EROFS, 0;
}
void tar_close(struct inode *this)
{
	(void) this;
	return;
}
int tar_stat(struct stat *buf, struct inode *node)
{
	buf->st_dev = node->dev;
	buf->st_ino = node->inode;
	buf->st_uid = node->uid;
	buf->st_gid = node->gid;
	buf->st_size = node->size;

	return 0;
}
unsigned int tar_getdents(unsigned int count, struct dirent* dirp, off_t off, struct inode* this)
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
char *get_complete_tar_path(struct inode *node, const char *name)
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
struct inode *tar_open(struct inode *this, const char *name)
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
			struct inode *node = malloc(sizeof(struct inode));
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
			memcpy(&node->fops, &this->fops, sizeof(struct file_ops));
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

void initrd_mount(void)
{
	tar_header_t **iter = headers;
	for(size_t i = 0; i < n_files; i++)
	{
		char *saveptr;
		char *filename = strdup(iter[i]->filename);
		char *old = filename;

		assert(filename != NULL);

		filename = dirname(filename);
		
		filename = strtok_r(filename, "/", &saveptr);

		struct inode *node = fs_root;
		if(*filename != '.' && strlen(filename) != 1)
		{

			while(filename)
			{
				struct inode *last = node;
				if(!(node = open_vfs(node, filename)))
				{
					node = last;
					if(!(node = mkdir_vfs(filename, 0777, node)))
					{
						perror("mkdir");
						panic("Error loading initrd");
					}
				}
				filename = strtok_r(NULL, "/", &saveptr);
			}
		}
		/* After creat/opening the directories, create it and populate it */
		strcpy(old, iter[i]->filename);
		filename = old;
		filename = basename(filename);

		if(iter[i]->typeflag == TAR_TYPE_FILE)
		{
			struct inode *file = creat_vfs(node, filename, 0666);
			assert(file != NULL);
	
			char *buffer = (char *) iter[i] + 512;
			size_t size = tar_get_size(iter[i]->size);
			assert(tmpfs_fill_with_data(file, buffer, size) != -1);
		}
		else if(iter[i]->typeflag == TAR_TYPE_DIR)
		{
			struct inode *file = mkdir_vfs(filename, 0666, node);

			assert(file != NULL);
		}
		else if(iter[i]->typeflag == TAR_TYPE_SYMLNK)
		{
			char *buffer = (char *) iter[i]->linkname;
			struct inode *file = creat_vfs(node, filename, 0666);
			assert(file != NULL);

			assert(symlink_vfs(buffer, file) == 0);
		}
	}
}

void init_initrd(void *initrd)
{
	printf("Found an Initrd at %p\n", initrd);
	n_files = tar_parse((uintptr_t) initrd);
	printf("Found %lu files in the Initrd\n", n_files);
	
	/* Mount a new instance of a tmpfs at / */
	tmpfs_mount("/");
	
	initrd_mount();
}
