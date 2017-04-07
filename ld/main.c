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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <libgen.h>

#include <sys/mman.h>
#include <sys/stat.h>

typedef struct linked_list
{
	void *data;
	struct linked_list *next;
} linked_list_t;
inline int list_insert(linked_list_t *list, void *obj)
{
	for(; list->next; list = list->next)
	{

	}
	list->next = malloc(sizeof(linked_list_t));
	if(!list->next)
		return -1;
	list->next->data = obj;
	list->next->next = NULL;

	return 0;
}
struct dso
{
	char *name;
	void *file;
	char *strtab;
	char *shstrtab;
	char *dynstr;
	int refcount;
	linked_list_t *dependencies;
	struct dso *next;
};
static struct dso *objects = NULL;
inline char *elf_get_string(Elf64_Word off, struct dso* obj)
{
	return obj->strtab + off;
}
inline char *elf_get_shstring(Elf64_Word off, struct dso* obj)
{
	return obj->shstrtab + off;
}
inline char *elf_get_dynstring(Elf64_Word off, struct dso* obj)
{
	return obj->dynstr + off;
}
inline void *elf_get_pointer(void *file, Elf64_Off offset)
{
	return (void*)(char*)file + offset;
}
size_t elf_get_object_size(struct dso *dso)
{
	Elf64_Ehdr *header = (Elf64_Ehdr *) dso->file;
	Elf64_Phdr *phdrs = elf_get_pointer(dso->file, header->e_phoff);

	uintptr_t lowest_address = UINT64_MAX;
	uintptr_t highest_address = 0;

	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if(phdrs[i].p_type == PT_LOAD)
		{
			if(phdrs[i].p_vaddr < lowest_address)
				lowest_address = phdrs[i].p_vaddr;
			if(phdrs[i].p_vaddr + phdrs[i].p_memsz > highest_address)
				highest_address = phdrs[i].p_vaddr + phdrs[i].p_memsz;
		}
	}

	return highest_address - lowest_address;
}
/* Utility function to read a whole file to a buffer - returns NULL on any failure */
void *read_file(const char *path)
{
	/* Get the size of the file */
	struct stat buf;
	memset(&buf, 0, sizeof(struct stat));
	if(stat(path, &buf) < 0)
		return NULL;
	size_t file_size = buf.st_size;
	/* Allocate a buffer with the apropriate size */
	void *buffer = malloc(file_size);
	if(!buffer)
		return NULL;

	/* Open the file and read it */
	FILE *fp = fopen(path, "rb");
	if(!fp)
	{
		free(buffer);
		return NULL;
	}
	size_t read = fread(buffer, 1, file_size, fp);
	if(read != file_size)
	{
		printf("read_file: read I/O error\n");
		fclose(fp);
		free(buffer);
		return NULL;
	}
	fclose(fp);
	return buffer;
}
/* Check if it's a valid elf64 x86_64 SYSV ABI file */
int verify_elf(void *file)
{
	Elf64_Ehdr *header = (Elf64_Ehdr *) file;
	if (header->e_ident[EI_MAG0] != ELFMAG0 || header->e_ident[EI_MAG1] != ELFMAG1 
		|| header->e_ident[EI_MAG2] != ELFMAG2 || header->e_ident[EI_MAG3] != ELFMAG3)
		return -1;
	if (header->e_ident[EI_CLASS] != ELFCLASS64)
		return -1;
	if (header->e_ident[EI_DATA] != ELFDATA2LSB)
		return -1;
	if (header->e_ident[EI_VERSION] != EV_CURRENT)
		return -1;
	if (header->e_ident[EI_OSABI] != ELFOSABI_SYSV)
		return -1;
	if (header->e_ident[EI_ABIVERSION] != 0)	/* SYSV specific */
		return -1;
	return 0;
}
char *find_library(char *libname)
{
	/* Right now we only check for /usr/lib/library, and /lib/library 
	   TODO: Implement LD_LIBRARY_PATH and similar things
	*/
	char *path = malloc(strlen("/usr/lib/") + strlen(libname) + 1);
	if(!path)
		return NULL;
	memset(path, 0, strlen("/usr/lib") + strlen(libname) + 1);
	strcpy(path, "/usr/lib/");
	strcat(path, libname);
	struct stat buf;
	if(stat(path, &buf) == 0) /* We found it, return */
		return path;
	/* Try again with /lib */
	memset(path, 0, strlen("/usr/lib") + strlen(libname) + 1);
	strcpy(path, "/lib/");
	strcat(path, libname);

	if(stat(path, &buf) == 0) /* We found it, return */
		return path;

	/* We couldn't find it, return NULL */
	free(path);
	return NULL;
}
struct dso *load_library(char *libname)
{
	Elf64_Ehdr *header;
	Elf64_Phdr *phdrs;
	Elf64_Shdr *sections;
	Elf64_Half n_sections;
	Elf64_Dyn *dyn = NULL;
	size_t n_dyn = 0;
	struct dso *object;
	char *path;
	for(struct dso *i = objects; i; i = i->next)
	{
		/* We've already loaded this, just return */
		if(!strcmp(i->name, libname))
		{
			i->refcount++;
			return i;
		}
	}
	path = find_library(libname);
	if(!path)
		return NULL;
	object = malloc(sizeof(struct dso));
	if(!object)
	{
		free(path);
		return NULL;
	}
	object->file = read_file(path);
	if(!object->file)
	{
		free(path);
		free(object);
		return NULL;
	}
	
	object->refcount = 1;
	object->next = NULL;
	header = (Elf64_Ehdr *) object->file;
	phdrs = elf_get_pointer(object->file, header->e_phoff);
	sections = elf_get_pointer(object->file, header->e_shoff);
	n_sections = header->e_shnum;

	/* Get the object's total size while loaded */
	size_t object_size = elf_get_object_size(object);

	/* and mmap it */
	printf("Size %u\n", object_size);
	void *base = mmap(NULL, object_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(base == MAP_FAILED)
		abort();
	printf("ld: shared lib base %p-%p\n", base, (uintptr_t) base + object_size);
	/* Firstly, load the library */
	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if (phdrs[i].p_type == PT_NULL)
			continue;
		if (phdrs[i].p_type == PT_LOAD)
		{
			phdrs[i].p_vaddr += (uintptr_t) base;
			
			memcpy((void*)phdrs[i].p_vaddr, elf_get_pointer(object->file, phdrs[i].p_offset), phdrs[i].p_memsz);
			int prot = ((phdrs[i].p_flags & PF_R) ? PROT_READ : 0) |
				   ((phdrs[i].p_flags & PF_W) ? PROT_WRITE : 0)|
				   ((phdrs[i].p_flags & PF_X) ? PROT_EXEC : 0);
			mprotect((void*)(phdrs[i].p_vaddr & 0xFFFFFFFFFFFFF000), phdrs[i].p_memsz, prot);
		}
		if(phdrs[i].p_type == PT_DYNAMIC)
		{
			dyn = elf_get_pointer(object->file, phdrs[i].p_offset);
			n_dyn = phdrs[i].p_filesz / sizeof(Elf64_Dyn);
		}
	}
	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if(phdrs[i].p_type == PT_LOAD)
		{
			/* TODO: See kernel/mm/vmm.c */
		}
	}
	if(!dyn)
		abort(); /* TODO: Appropriately handle this, abort() seems too severe */

	for(struct dso *i = objects; i; i = i->next)
	{
		/* We've already loaded this, just return */
		if(!i->next)
		{
			i->next = object;
		}
	}

	printf("Found the library at %s\n", path);
	return object;
}
int load_elf(void *file, char *path)
{
	Elf64_Ehdr *header = (Elf64_Ehdr *) file;
	Elf64_Phdr *phdrs = elf_get_pointer(file, header->e_phoff);
	struct dso *object = malloc(sizeof(struct dso));
	if(!object)
		abort();
	memset(object, 0, sizeof(struct dso));
	Elf64_Shdr *sections = elf_get_pointer(file, header->e_shoff);
	Elf64_Half n_sections = header->e_shnum;
	Elf64_Dyn *dyn = NULL;
	size_t n_dyn = 0;
	/* Firstly, load the program itself */
	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if (phdrs[i].p_type == PT_NULL)
			continue;
		if (phdrs[i].p_type == PT_LOAD)
		{
			/* The main elf program's memory is already mmap'd, so just memcpy it */
			memcpy((void*) phdrs[i].p_vaddr, elf_get_pointer(file, phdrs[i].p_offset), phdrs[i].p_filesz);
		}
		if(phdrs[i].p_type == PT_DYNAMIC)
		{
			dyn = elf_get_pointer(file, phdrs[i].p_offset);
			n_dyn = phdrs[i].p_filesz / sizeof(Elf64_Dyn);
		}
	}
	if(!dyn)
		abort(); /* TODO: Appropriately handle this, abort() seems too severe */
	object->file = file;
	object->shstrtab = elf_get_pointer(file, sections[header->e_shstrndx].sh_offset);
	object->name = basename(path);
	object->refcount = 1;
	objects = object;
	/* Parse through the sections, looking for the sections we're interested in */
	for(Elf64_Half i = 0; i < n_sections; i++)
	{
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".strtab") == 0)
			object->strtab = elf_get_pointer(file, sections[i].sh_offset);
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".dynstr") == 0)
			object->dynstr = elf_get_pointer(file, sections[i].sh_offset);
	}
	/* Parse through the DYNAMIC section, and load the needed libraries */
	for(size_t i = 0; i < n_dyn; i++)
	{
		switch(dyn[i].d_tag)
		{
			case DT_NEEDED:
			{
				printf("ld: loading %s\n", elf_get_dynstring(dyn[i].d_un.d_val, object));
				struct dso *lib = load_library(elf_get_dynstring(dyn[i].d_un.d_val, object));
				if(!lib)
				{
					printf("Failed to load %s\n", elf_get_dynstring(dyn[i].d_un.d_val, object));
					return 1;
				}
				if(!object->dependencies)
				{
					object->dependencies = malloc(sizeof(linked_list_t));
					if(!object->dependencies)
						abort();
					object->dependencies->data = lib;
					object->dependencies->next = NULL;
				}
				else
				{
					if(list_insert(object->dependencies, lib) < 0)
						abort();
				}
			}
		}
	}
	
	while(1);
	return 0;
}
int load_prog(const char *filename)
{
	/* Read the file */
	void *file = read_file(filename);
	if(!file)
		return 1;
	/* and check if it's valid */
	if(verify_elf(file) < 0)
	{
		free(file);
		return 1;
	}
	/* and load it */
	return load_elf(file, (char*) filename);
}
int main(int argc, char **argv)
{
	/* In our case, argv[0] is the to-be-loaded program's name*/
	return load_prog((const char *) argv[0]);
}