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
namespace Initrd
{
static tar_header_t* headers[100];
static fs_node_t* root_fs;
static fs_node_t* nodes;

uint32_t GetSize(const char* in)
{

	unsigned int size = 0;
	unsigned int j;
	unsigned int count = 1;

	for (j = 11; j > 0; j--, count *= 8)
		size += ((in[j - 1] - '0') * count);

	return size;

}
unsigned int Parse(uint32_t address)
{

	unsigned int i;

	for (i = 0; ; i++)
	{

		tar_header_t* header = (tar_header_t*)address;

		if (header->filename[0] == '\0')
			break;
		unsigned int size = GetSize(header->size);

		headers[i] = header;

		address += ((size / 512) + 1) * 512;

		if (size % 512)
			address += 512;
	}

	return i;

}
uint32_t tar_read(fs_node_t* node,uint32_t offset,uint32_t size,void* buffer)
{
	tar_header_t* header = headers[node->inode];
	if(offset + size > GetSize(header->size))
		return 1;
	void* data = (void*)header + 512 + offset;
	memcpy(buffer,data,size);

	return GetSize(header->size);
}
struct dirent dirent;
static unsigned int NUM_FILES;
static struct dirent* tar_readdir(fs_node_t* node,uint32_t index)
{

	if(node == root_fs){
		strcpy(dirent.name, "/dev/initfs\0");
		dirent.ino = 0;
		return &dirent;
	}
	if(index >= NUM_FILES)
		return NULL;

	strcpy(dirent.name,nodes[index].name);
	dirent.ino = nodes[index].inode;
	return &dirent;
}
static fs_node_t* tar_finddir(fs_node_t* node,char* name)
{
	if(node->flags == FS_ROOT){

		for(unsigned int i = 0;i < NUM_FILES;i++){
			if(strcmp(name,nodes[i].name)==0){
				return &nodes[i];
			}
		}
	}else{
		for(unsigned int i = 0;i < NUM_FILES;i++){
			if(strcmp(strcat(node->name,name),nodes[i].name)==0){
				return &nodes[i];
			}
		}
	}
	return nullptr;
}

fs_node_t* Init(uint32_t addr)
{
	if(addr < 0x100000) // GRUB doesn't load anything below 0x100000 (1 MiB)
		panic("Invalid initrd address.");

	printf("Found initrd module at 0x%X\n",addr);

	unsigned int num_files = Parse(addr);

	NUM_FILES = num_files;

	printf("Found %i files in initrd\n",num_files);

	root_fs = (fs_node_t*)kmalloc(sizeof(fs_node_t));

	if(!root_fs)
		panic("Not enough memory!");
	memset(root_fs,0,sizeof(fs_node_t));
	strcpy(root_fs->name,"/dev/initfs");

	root_fs->inode = 0;
	root_fs->flags = FS_ROOT;
	root_fs->readdir = &tar_readdir;
	root_fs->finddir = &tar_finddir;
	nodes = (fs_node_t*)kmalloc(sizeof(fs_node_t) * num_files);
	if(!nodes)
		panic("Not enough memory!");

	memset(nodes,0,sizeof(fs_node_t) * num_files);

	for(uint32_t i = 0;i < num_files;i++){

		fs_node_t* node = &nodes[i];
		strcpy(node->name,"/");
		strcpy(node->name + 1,headers[i]->filename);

		if(headers[i]->typeflag == TAR_TYPE_DIR)
			node->flags = FS_DIRECTORY;
		else
			node->flags = FS_FILE;
		//TODO:^^ Add support to more file types
		node->inode = i;
		node->read = &tar_read;
		node->readdir = &tar_readdir;
		node->finddir = &tar_finddir;
		node->length = GetSize(headers[i]->size);
	}

	return root_fs;
}
}
