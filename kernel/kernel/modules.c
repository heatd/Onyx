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
#include <kernel/modules.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <kernel/vfs.h>
#include <kernel/elf.h>
#include <kernel/vmm.h>
static module_hashtable_t *hashtable;
_Bool mods_disabled = 0;
#define DEFAULT_SIZE 100
int initialize_module_subsystem()
{
	hashtable = malloc(sizeof(module_hashtable_t));
	if(!hashtable)
	{
		printf("Kernel modules disabled. Not enough memory.\n");
		mods_disabled = 1;
		return errno = ENOMEM;
	}
	memset(hashtable, 0, sizeof(module_hashtable_t));
	hashtable->size = DEFAULT_SIZE;
	hashtable->buckets = malloc(DEFAULT_SIZE * sizeof(void*));
	return 0;
}
static int generate_key(const char *path, const char *name)
{
	int n = *name;
	int m = *path + 3;
	int key = 1;
	for(int i = 0; i < 8; i++)
		key *= n + m;
	key = key % hashtable->size;
	printf("Key: %d\n", key);
	return key;
}
int add_module_to_hashtable(module_t *mod)
{
	int key = generate_key(mod->path, mod->name);

	if(hashtable->buckets[key] == NULL)
	{
		hashtable->buckets[key] = mod;
	}
	else
	{
		module_t *i = hashtable->buckets[key];
		for(; i->next != NULL; i=i->next);
		i->next = mod;
	}
	return key;
}
module_t *get_module_from_key(int key, char *name)
{
	if(key > DEFAULT_SIZE)
		return errno = EINVAL, NULL;
	if(hashtable->buckets[key] == NULL)
		return errno = EINVAL, NULL;
	for(module_t *i = hashtable->buckets[key]; i != NULL; i = i->next)
	{
		if(strcmp((char*)i->name, name)==0)
			return i;
	}
	return errno = EINVAL, NULL;
}
int load_module(const char *path, const char *name)
{	
	module_t *mod = malloc(sizeof(module_t));
	if(!mod)
	{
		printf("Kernel modules disabled. Not enough memory.\n");
		mods_disabled = 1;
		return errno = ENOMEM;
	}
	mod->path = path;
	mod->name = name;
	vfsnode_t *file = open_vfs(fs_root, path);
	if(!file)
	{
		if(errno == ENOMEM)
			mods_disabled = 1;
		return 1;
	}
	char *buffer = malloc(file->size);
	memset(buffer, 0, file->size);
	if (!buffer)
		return errno = ENOMEM;
	size_t read = read_vfs(0, file->size, buffer, file);
	if (read != file->size)
		return errno = EAGAIN;
	void *fini;
	void *entry = elf_load_kernel_module(buffer, &fini);
	if(errno == EINVAL)
		printf("Invalid ELF file\n");
	module_init_t *functor = (module_init_t*) entry;
	printf("Functor: %p\n", functor);
	functor();
	return add_module_to_hashtable(mod);
}
uintptr_t last_kernel_address = KERNEL_VIRTUAL_BASE + 0x600000;
void *allocate_module_memory(size_t size)
{
	size_t pages = size / PAGE_SIZE;
	if(size % PAGE_SIZE)
		pages++;
	void *ret = (void*) last_kernel_address;
	vmm_map_range(ret, pages, VMM_WRITE|VMM_GLOBAL);
	last_kernel_address += pages * PAGE_SIZE;
	return ret;
}