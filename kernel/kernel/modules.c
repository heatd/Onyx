/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <onyx/modules.h>
#include <onyx/vfs.h>
#include <onyx/elf.h>
#include <onyx/vm.h>

static module_hashtable_t *hashtable;
bool mods_disabled = 0;
#define DEFAULT_SIZE 100

int initialize_module_subsystem(void)
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
	
	if(!hashtable->buckets)
	{
		printf("Kernel modules disabled. Not enough memory.\n");
		mods_disabled = 1;
		return errno = ENOMEM;
	}
	
	memset(hashtable->buckets, 0, DEFAULT_SIZE * sizeof(void*));
	return 0;
}

static int generate_key(const char *path, const char *name)
{
	int n = *name;
	int m = *path + 3;
	int key = 1;
	for(int i = 0; i < 8; i++)
		key += n + m;
	key = key % hashtable->size;
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
		for(; i->next != NULL; i = i->next);

		i->next = mod;
	}
	mod->next = NULL;
	return 0;
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
	
	mod->path = strdup(path);
	mod->name = strdup(name);
	mod->next = NULL;
	
	struct inode *file = open_vfs(get_fs_root(), path);
	if(!file)
	{
		if(errno == ENOMEM)
			mods_disabled = 1;
		free(mod);
		return 1;
	}
	
	char *buffer = malloc(file->i_size);
	
	if (!buffer)
		return errno = ENOMEM;
	memset(buffer, 0, file->i_size);
	
	size_t read = read_vfs(0, 0, file->i_size, buffer, file);
	if (read != file->i_size)
		return errno = EAGAIN;
	
	void *fini;
	
	void *entry = elf_load_kernel_module(buffer, &fini);
	if(!entry)
		return 1;
	
	if(errno == EINVAL)
		printf("Invalid ELF file\n");
	
	module_init_t *functor = (module_init_t*) entry;
	
	functor();
	
	mod->fini = (module_fini_t) fini;
	return add_module_to_hashtable(mod);
}

uintptr_t last_kernel_address = KERNEL_VIRTUAL_BASE + 0x600000;
void *allocate_module_memory(size_t size)
{
	size_t pages = size / PAGE_SIZE;
	if(size % PAGE_SIZE)
		pages++;
	void *ret = (void*) last_kernel_address;
	vm_map_range(ret, pages, VM_WRITE);
	last_kernel_address += pages * PAGE_SIZE;
	return ret;
}

struct common_block
{
	const char *symbol;
	void *buf;
	size_t size;
	struct common_block *next;
};

struct common_block *blocks = NULL;

uintptr_t get_common_block(const char *name, size_t size)
{
	struct common_block *h = blocks;

	for(; h != NULL; h = h->next)
	{
		if(!strcmp(h->symbol, name))
			return (uintptr_t) h->buf;
	}

	size_t pages = size / PAGE_SIZE;
	if(size % PAGE_SIZE)
		pages++;
	
	struct common_block *b = zalloc(sizeof(struct common_block));
	if(!b)
		return 0;
	b->symbol = strdup(name);
	b->buf = allocate_module_memory(size);
	b->size = size;

	struct common_block **i = &blocks;

	while(*i)
		i = &(*i)->next;
	*i = b;

	return (uintptr_t) b->buf;
}

int sys_insmod(const char *path, const char *name)
{
	if(!vm_is_mapped((void*) path))
		return errno =-EFAULT;
	if(!vm_is_mapped((void*) name))
		return errno =-EFAULT;
	/* All the work is done by load_module; A return value of 1 means -1
		for user-space, while -0 still = 0 */
	return -load_module(path, name);
}

void module_dump(void)
{
	if(!hashtable)
		return;
	module_t **buckets = hashtable->buckets;
	printk("Loaded modules: ");
	for(int i = 0; i < DEFAULT_SIZE; i++)
	{
		module_t *mod = buckets[i];
		if(!mod)
			continue;
		while(mod)
		{
			printk("%s ", mod->name);
			mod = mod->next;
		}
	}

	printk("\n");
}
