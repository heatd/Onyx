/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <elf.h>
#include <time.h>
#include <assert.h>

#include <onyx/log.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>
#include <onyx/vdso.h>
#include <onyx/compiler.h>
#include <onyx/clock.h>
#include <onyx/x86/tsc.h>

#include <sys/time.h>

extern Elf64_Ehdr __vdso_start;
extern size_t __vdso_end;

void increment_vdso_pages(void)
{
	uintptr_t vdso = (uintptr_t) &__vdso_start;
	size_t vdso_size = (uintptr_t) &__vdso_end - vdso;
	size_t pages = vm_align_size_to_pages(vdso_size);

	vdso -= KERNEL_VIRTUAL_BASE;
	for(size_t i = 0; i < pages; i++, vdso += PAGE_SIZE)
	{
		page_ref(phys_to_page(vdso));
	}
}

void *map_vdso(void)
{
#ifdef CONFIG_NO_VDSO
	return NULL;
#else
	uintptr_t vdso = (uintptr_t) &__vdso_start;
	size_t vdso_size = (uintptr_t) &__vdso_end - vdso;
	void *pages = get_user_pages(VM_TYPE_SHARED, vm_align_size_to_pages(vdso_size),
		VM_WRITE | VM_USER);
	if(!pages)
		return NULL;
	if(!map_pages_to_vaddr(pages, (void *)(vdso - KERNEL_VIRTUAL_BASE),
		vdso_size, VM_WRITE | VM_USER))
		return NULL;
	increment_vdso_pages();
	return pages;
#endif
}

static char *elf_get_name(Elf64_Half off, char *buf)
{
	return buf + off;
}

static uintptr_t vdso_base;
static Elf64_Sym *vdso_symtab = NULL;
static size_t nr_sym = 0;
static char *vdso_strtab = NULL;

void *vdso_lookup_symbol(const char *name)
{
	Elf64_Sym *s = vdso_symtab;
	for(size_t i = 0; i < nr_sym; i++, s++)
	{
		const char *symname = (const char *) elf_get_name(s->st_name, vdso_strtab);
		if(!strcmp(symname, name))
			return (void *) (vdso_base + s->st_value);
	}
	return NULL;
}

static struct clock_time *clock_realtime = NULL;
static struct clock_time *clock_monotonic = NULL;
static bool vdso_setup = false;

int vdso_update_time(clockid_t id, struct clock_time *time)
{
	if(!vdso_setup)
		return 0;
	/* First, get the corresponding symbol */
	struct clock_time *t = NULL;
	if(id == CLOCK_REALTIME)
		t = clock_realtime;
	else if(id == CLOCK_MONOTONIC)
		t = clock_monotonic;
	
	/* If we didn't find the symbol/the clock isn't in the vdso, return an error */
	if(!t)
		return errno = EINVAL, -1;
	*t = *time;

	return 0;
}

/* Ubsan is being stupid so I need to shut it up */
__attribute__((no_sanitize_undefined))
void vdso_init(void)
{
	uintptr_t page = (uintptr_t) &__vdso_start;
	size_t vdso_size = (uintptr_t) &__vdso_end - page;
	size_t vdso_pages = vm_align_size_to_pages(vdso_size);

	page -= KERNEL_VIRTUAL_BASE;

	for(size_t i = 0; i < vdso_pages; i++, page += PAGE_SIZE)
		page_add_page((void *) page);

	increment_vdso_pages();

	char *file = (char *) &__vdso_start;
	Elf64_Ehdr *header = (Elf64_Ehdr *) &__vdso_start;

	assert(header->e_ident[EI_MAG0] == '\x7f');

	Elf64_Shdr *s = (Elf64_Shdr*)(file + header->e_shoff);
	Elf64_Shdr *shname = &s[header->e_shstrndx];
	Elf64_Phdr *ph = (Elf64_Phdr*)(file + header->e_phoff);
	vdso_base = (uintptr_t) file + ph->p_offset;

	char *shname_buf = (char*)(file + shname->sh_offset);
	for(Elf64_Half i = 0; i < header->e_shnum; i++)
	{
		char *name = elf_get_name(s[i].sh_name, shname_buf);
		if(!strcmp(name, ".symtab"))
		{
			vdso_symtab = (void*)(file + s[i].sh_offset);
			nr_sym = s[i].sh_size / s[i].sh_entsize;
		}
		else if(!strcmp(name, ".strtab"))
		{
			vdso_strtab = (void*)(file + s[i].sh_offset);
		}
	}

	struct vdso_time *time = vdso_lookup_symbol("__time");

	/* Configure the vdso with tsc stuff */
	tsc_setup_vdso(time);

	clock_monotonic = vdso_lookup_symbol("clock_monotonic");
	clock_realtime = vdso_lookup_symbol("clock_realtime");
	
	vdso_setup = true;

	/* Update the vdso for the first time */
	vdso_update_time(CLOCK_MONOTONIC, get_raw_clock_time(CLOCK_MONOTONIC));
	vdso_update_time(CLOCK_REALTIME, get_raw_clock_time(CLOCK_REALTIME));
}