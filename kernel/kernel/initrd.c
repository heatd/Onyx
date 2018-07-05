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

		struct inode *node = get_fs_root();
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
