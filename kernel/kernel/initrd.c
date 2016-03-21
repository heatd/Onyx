/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**************************************************************************
 *
 *
 * File: initrd.cpp
 *
 * Description: Contains the code to read the initrd
 *
 * Date: 4/3/2016
 *
 *
 **************************************************************************/
#include <kernel/initrd.h>
#include <kernel/panic.h>
#include <stdio.h>
#include <stdbool.h>
#include <kernel/kheap.h>
#include <kernel/tty.h>
#include <kernel/compiler.h>
#include <string.h>
#include <stdlib.h>
static tar_header_t *headers[100];
static fs_node_t *root_fs;
static fs_node_t *nodes;
static fs_node_t *last;
static uint32_t inode = 0;
uint32_t gen_inode()
{
	inode++;
	return inode - 1;
}

uint32_t tar_get_size(const char *in)
{

	unsigned int size = 0;
	unsigned int j;
	unsigned int count = 1;

	for (j = 11; j > 0; j--, count *= 8)
		size += ((in[j - 1] - '0') * count);

	return size;

}

unsigned int tar_parse(uint32_t address)
{

	unsigned int i;

	for (i = 0;; i++) {

		tar_header_t *header = (tar_header_t *) address;

		if (header->filename[0] == '\0')
			break;
		unsigned int size = tar_get_size(header->size);

		headers[i] = header;

		address += ((size / 512) + 1) * 512;

		if (size % 512)
			address += 512;
	}

	return i;

}

static uint32_t NUM_FILES;
fs_node_t *root_open(fs_node_t * node, const char *name)
{
	if (!node) {
		// If the node is invalid, create one
		fs_node_t *open = kmalloc(sizeof(fs_node_t));
		memset(open, 0, sizeof(fs_node_t));
		open->open = root_open;
		strcpy(open->name, name);
		open->inode = gen_inode();
		last->next = open;
		last = open;
		NUM_FILES++;
		return open;
	} else {
		// Implement fs permitions
		return node;
	}
}

uint32_t tar_read(fs_node_t * node, uint32_t offset, uint32_t size,
		  void *buffer)
{
	tar_header_t *header = headers[node->inode];
	if (offset + size > tar_get_size(header->size))
		return 1;
	void *data = (void *) header + 512 + offset;
	memcpy(buffer, data, size);

	return tar_get_size(header->size);
}

struct dirent *dirent;
static struct dirent *tar_readdir(fs_node_t * node, uint32_t index)
{
	if (index > NUM_FILES)
		return NULL;
	dirent = kmalloc(sizeof(struct dirent));

	fs_node_t *search = nodes;
	for (unsigned int i = 0; i < index; i++) {
		search = search->next;
	}
	strcpy(dirent->name, search->name);
	dirent->ino = search->inode;
	return dirent;
}

static fs_node_t *tar_finddir(fs_node_t * node, char *name)
{
	fs_node_t *search = nodes;
	if (node->flags == FS_ROOT) {

		for (unsigned int i = 0; i < NUM_FILES; i++) {
			if (strcmp(name, search->name) == 0) {
				return search;
			}
			search = search->next;
		}
	} else if (node->flags == FS_MOUNTPOINT) {
		for (unsigned int i = 0; i < NUM_FILES; i++) {
			if (strcmp(name, search->ptr->name) == 0) {
				return search->ptr;
			}
			search = search->next;
		}
	} else {
		for (unsigned int i = 0; i < NUM_FILES; i++) {
			if (strcmp(strcat(node->name, name), search->name)
			    == 0) {
				return search;
			}
			search = search->next;
		}
	}
	return NULL;
}

fs_node_t *initrd_init(uint32_t addr)
{
	if (addr < 0x100000)	// GRUB doesn't load anything below 0x100000 (1 MiB)
		panic("Invalid initrd address.");

	printf("Found initrd module at 0x%X\n", addr);

	unsigned int num_files = tar_parse(addr);

	NUM_FILES = num_files;

	printf("Found %i files in initrd\n", num_files);

	root_fs = (fs_node_t *) kmalloc(sizeof(fs_node_t));

	if (!root_fs)
		panic("Not enough memory!");
	memset(root_fs, 0, sizeof(fs_node_t));
	strcpy(root_fs->name, "/dev/initfs");

	root_fs->inode = 0;
	root_fs->flags = FS_ROOT;
	root_fs->readdir = &tar_readdir;
	root_fs->finddir = &tar_finddir;
	root_fs->open = &root_open;
	nodes = (fs_node_t *) kmalloc(sizeof(fs_node_t) * num_files);
	last = root_fs;
	if (!nodes)
		panic("Not enough memory!");

	memset(nodes, 0, sizeof(fs_node_t) * num_files);

	for (uint32_t i = 0; i < num_files; i++) {

		fs_node_t *node = &nodes[i];
		strcpy(node->name, "/");
		strcpy(node->name + 1, headers[i]->filename);
		last->next = node;
		if (headers[i]->typeflag == TAR_TYPE_DIR)
			node->flags = FS_DIRECTORY;
		else
			node->flags = FS_FILE;
		//TODO:^^ Add support to more file types
		node->inode = gen_inode();
		node->read = &tar_read;
		node->readdir = &tar_readdir;
		node->finddir = &tar_finddir;
		node->length = tar_get_size(headers[i]->size);
		last = node;
	}

	return root_fs;
}
