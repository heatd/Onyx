/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <libgen.h>
#include <limits.h>
#include <utils.h>
#include <dynlink.h>

#include <sys/mman.h>
#include <sys/stat.h>

#define PATH_MAX 4096

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
inline Elf64_Sym *elf_get_sym(size_t idx, struct dso *dso)
{
	return &dso->dyntab[idx];
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
char *default_lib_path = "/usr/lib:/lib";
char *find_library(char *libname)
{
	char *saveptr = NULL;
	/* Get the library path */
	char *library_path = getenv("LD_LIBRARY_PATH");
	if(!library_path) library_path = default_lib_path;

	/* strdup it */
	library_path = strdup(library_path);
	if(!library_path)
		return NULL;

	struct stat buf = {0};

	/* Allocate a large enough path */
	char *path = malloc(PATH_MAX);
	if(!path)
		return NULL;
	memset(path, 0, PATH_MAX);

	/* Tokenize the string and parse through it */
	char *p = strtok_r(library_path, ":", &saveptr);

	while(p)
	{
		memset(path, 0, strlen(path));
		if(snprintf(path, PATH_MAX, "%s/%s", p, libname) > PATH_MAX)
		{
			printf("ld: %s/%s: ENAMETOOLONG\n", p, libname);
			return NULL;
		}

		if(stat(path, &buf) == 0)
			return path;
		p = strtok_r(NULL, ":", &saveptr);
	}
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
	object->name = libname;
	object->next = NULL;
	header = (Elf64_Ehdr *) object->file;
	phdrs = elf_get_pointer(object->file, header->e_phoff);
	sections = elf_get_pointer(object->file, header->e_shoff);
	n_sections = header->e_shnum;
	object->shstrtab = elf_get_pointer(object->file, sections[header->e_shstrndx].sh_offset);
	/* Get the object's total size while loaded */
	size_t object_size = elf_get_object_size(object);

	/* and mmap it */
	void *base = mmap(NULL, object_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if(base == MAP_FAILED)
		abort();
	object->base = (uintptr_t) base;
	printf("ld: shared lib base %p-%p\n", base, (uintptr_t) base + object_size);
	/* Firstly, load the library */
	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if (phdrs[i].p_type == PT_NULL)
			continue;
		if (phdrs[i].p_type == PT_LOAD)
		{
			phdrs[i].p_vaddr += (uintptr_t) base;

			memcpy((void*) phdrs[i].p_vaddr, elf_get_pointer(object->file, phdrs[i].p_offset), phdrs[i].p_filesz);
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
	if(!dyn)
		abort(); /* TODO: Appropriately handle this, abort() seems too severe */

	for(struct dso *i = objects; i; i = i->next)
	{
		if(!i->next)
		{
			i->next = object;
			break;
		}
	}
	for(Elf64_Half i = 0; i < n_sections; i++)
	{
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".strtab") == 0)
			object->strtab = elf_get_pointer(object->file, sections[i].sh_offset);
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".dynstr") == 0)
			object->dynstr = elf_get_pointer(object->file, sections[i].sh_offset);
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".symtab") == 0)
		{
			object->symtab = elf_get_pointer(object->file, sections[i].sh_offset);
			object->nr_symtab = sections[i].sh_size / sections[i].sh_entsize;
		}
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".dynsym") == 0)
		{
			object->dyntab = elf_get_pointer(object->file, sections[i].sh_offset);
			object->nr_dyntab = sections[i].sh_size / sections[i].sh_entsize;
		}
	}
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
					return NULL;
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
				break;
			}
			case DT_INIT:
			{
				object->init = (void (*)()) dyn[i].d_un.d_ptr;
				break;
			}
			case DT_FINI:
			{
				object->fini = (void (*)()) dyn[i].d_un.d_ptr;
				break;
			}
			case DT_INIT_ARRAY:
			{
				object->initarray = (void*) dyn[i].d_un.d_ptr;
				break;
			}
			case DT_INIT_ARRAYSZ:
			{
				object->initarraysz = dyn[i].d_un.d_ptr;
				break;
			}
			case DT_FINI_ARRAY:
			{
				object->finiarray = (void*) dyn[i].d_un.d_ptr;
				break;
			}
			case DT_FINI_ARRAYSZ:
			{
				object->finiarraysz = dyn[i].d_un.d_ptr;
				break;
			}
		}
	}
	printf("Found the library at %s\n", path);
	return object;
}
Elf64_Sym *lookup_symbol(char *name, struct dso *dso)
{
	linked_list_t *dependencies = dso->dependencies;
	for(; dependencies; dependencies = dependencies->next)
	{
		struct dso *object = dependencies->data;
		Elf64_Sym *symtab = object->dyntab;
		for(Elf64_Half i = 0; i < object->nr_dyntab; i++)
		{
			if(strcmp(elf_get_dynstring(symtab[i].st_name, object), name) == 0)
			{
				symtab[i].st_value += object->base;
				return &symtab[i];
			}
		}
	}
	return NULL;
}
int resolve_dependencies(struct dso *dso)
{
	printf("Resolving the dependencies of %s\n", dso->name);
	Elf64_Sym *symtab = dso->symtab;
	Elf64_Ehdr *header = (Elf64_Ehdr *) dso->file;
	Elf64_Shdr *sections = elf_get_pointer(dso->file, header->e_shoff);
	Elf64_Half n_sections = header->e_shnum;
	for(Elf64_Half i = 0; i < n_sections; i++)
	{
		if(sections[i].sh_type == SHT_RELA)
		{
			Elf64_Rela *r = elf_get_pointer(dso->file, sections[i].sh_offset);
			for(size_t j = 0; j < sections[i].sh_size / sections[i].sh_entsize; j++)
			{
				Elf64_Rela *rela = &r[j];
				rela->r_offset += (uintptr_t) dso->base;
				uintptr_t *addr = (uintptr_t*) rela->r_offset;

				size_t sym_index = ELF64_R_SYM(rela->r_info);
				Elf64_Sym *symbol;
				if(sym_index != 0)
				{
					symbol = elf_get_sym(sym_index, dso);
					if(!symbol)
						return -1;
					char *symbol_name = elf_get_dynstring(symbol->st_name, dso);
					symbol->st_value += dso->base;
					if(ELF64_ST_BIND(symbol->st_info) & STB_WEAK)
					{
						printf("Resolving weak symbol %s\n", symbol_name);
						symbol = lookup_symbol(symbol_name, dso);
					}
					if(symbol->st_shndx == STN_UNDEF) /* symbol is undefined, look for the actual one */
						symbol = lookup_symbol(symbol_name, dso);
					if(!symbol)
					{
						printf("Unresolved symbol %s\n", symbol_name);
						return -1;
					}
					printf("Symbol <%s> value: %p\n", symbol_name, symbol->st_value);
				}
				switch(ELF64_R_TYPE(rela->r_info))
				{
					case R_X86_64_RELATIVE:
						*addr = RELOCATE_R_X86_64_RELATIVE(dso->base, rela->r_addend);
						break;
					case R_X86_64_JUMP_SLOT:
						*addr = RELOCATE_R_X86_64_JUMP_SLOT(symbol->st_value);
						break;
					case R_X86_64_64:
						*addr = RELOCATE_R_X86_64_64(symbol->st_value, rela->r_addend);
						break;
					case R_X86_64_GLOB_DAT:
						*addr = RELOCATE_R_X86_64_GLOB_DAT(symbol->st_value);
						break;
					case R_X86_64_COPY:
						memcpy(addr, symbol->st_value, symbol->st_size);
						break;
					default:
						printf("Unhandled relocation type %u\n", ELF64_R_TYPE(rela->r_info));
						return -1;
				}
			}
		}
	}

	for(linked_list_t *dep = dso->dependencies; dep; dep = dep->next)
	{
		if(resolve_dependencies(dep->data) < 0)
			return -1;
	}
	return 0;
}
void do_init(struct dso *dso)
{
	printf("Doing init for %s!\n", dso->name);
	if(dso->init)
	{
		fpaddr(dso->init, dso)();
	}
	else if(dso->initarray)
	{
		size_t nr_initarray = dso->initarraysz/sizeof(void*);
		void (**initarray)() = (void (**)()) dso->initarray; 
		for(size_t i = 0; i < nr_initarray; i++)
		{
			fpaddr(initarray[i], dso)();
		}
	}
}
void *load_elf(void *file, char *path)
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
	object->base = 0;
	objects = object;
	/* Parse through the sections, looking for the sections we're interested in */
	for(Elf64_Half i = 0; i < n_sections; i++)
	{
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".strtab") == 0)
			object->strtab = elf_get_pointer(file, sections[i].sh_offset);
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".dynstr") == 0)
			object->dynstr = elf_get_pointer(file, sections[i].sh_offset);
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".dynsym") == 0)
			object->dyntab = elf_get_pointer(file, sections[i].sh_offset);
		if(strcmp(elf_get_shstring(sections[i].sh_name, object), ".symtab") == 0)
			object->symtab = elf_get_pointer(object->file, sections[i].sh_offset);
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
					return NULL;
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
				break;
			}
			case DT_INIT:
			{
				object->init = (void (*)()) dyn[i].d_un.d_ptr;
				break;
			}
			case DT_FINI:
			{
				object->fini = (void (*)()) dyn[i].d_un.d_ptr;
				break;
			}
			case DT_INIT_ARRAY:
			{
				object->initarray = (void*) dyn[i].d_un.d_ptr;
				break;
			}
			case DT_INIT_ARRAYSZ:
			{
				object->initarraysz = dyn[i].d_un.d_ptr;
				break;
			}
			case DT_FINI_ARRAY:
			{
				object->finiarray = (void*) dyn[i].d_un.d_ptr;
				break;
			}
			case DT_FINI_ARRAYSZ:
			{
				object->finiarraysz = dyn[i].d_un.d_ptr;
				break;
			}
		}
	}
	if(resolve_dependencies(object) < 0)
		return NULL;
	/* Do init */
	for(struct dso *dso = objects; dso; dso = dso->next)
	{
		do_init(dso);
	}
	return (void*) header->e_entry;
}
void *load_prog(const char *filename)
{
	/* Read the file */
	void *file = read_file(filename);
	if(!file)
		return NULL;
	/* and check if it's valid */
	if(verify_elf(file) < 0)
	{
		free(file);
		return NULL;
	}
	/* and load it */
	return load_elf(file, (char*) filename);
}
extern char **environ;
int main(int argc, char **argv, char **envp, void *auxv)
{
	/* In our case, argv[0] is the to-be-loaded program's name*/
	void *retval = load_prog((const char *) argv[0]);
	if(retval)
	{
		/* Launch the program */
		prog_entry_t start = (prog_entry_t) retval;
		start(argc, argv, envp, auxv); 
	}
	return 1;
}
