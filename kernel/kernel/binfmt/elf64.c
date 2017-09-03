/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <stdio.h>

#include <kernel/binfmt/elf64.h>
#include <kernel/vmm.h>

static bool elf64_is_valid(Elf64_Ehdr *header)
{
	if (header->e_ident[EI_MAG0] != 0x7F || header->e_ident[EI_MAG1] != 'E' || header->e_ident[EI_MAG2] != 'L' || header->e_ident[EI_MAG3] != 'F')
		return false;
	if (header->e_ident[EI_CLASS] != ELFCLASS64)
		return false;
	if (header->e_ident[EI_DATA] != ELFDATA2LSB)
		return false;
	if (header->e_ident[EI_VERSION] != EV_CURRENT)
		return false;
	if (header->e_ident[EI_OSABI] != ELFOSABI_SYSV)
		return false;
	if (header->e_ident[EI_ABIVERSION] != 0)	/* SYSV specific */
		return false;
	return true;
}

void *elf64_load_static(struct binfmt_args *args, Elf64_Ehdr *header)
{
	size_t program_headers_size = header->e_phnum * header->e_phentsize;
	Elf64_Phdr *phdrs = malloc(program_headers_size);
	if(!phdrs)
		return errno = ENOMEM, NULL;

	/* Read the program header */

	read_vfs(0, header->e_phoff, program_headers_size, phdrs, args->file);

	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if(phdrs[i].p_type == PT_NULL)
			continue;
		if(phdrs[i].p_type == PT_LOAD)
		{
			uintptr_t aligned_address = phdrs[i].p_vaddr & 0xFFFFFFFFFFFFF000;
			size_t total_size = phdrs[i].p_memsz + (phdrs[i].p_vaddr - aligned_address);
			size_t pages = total_size / PAGE_SIZE;
			if(total_size % PAGE_SIZE)
				pages++;

			/* Sanitize the address first */
			if(vm_sanitize_address((void*) aligned_address, pages) < 0)
			{
				free(phdrs);
				return errno = EINVAL, NULL;
			}

			int prot = (VM_USER) |
				   ((phdrs[i].p_flags & PF_W) ? VM_WRITE : 0) |
				   ((phdrs[i].p_flags & PF_X) ? 0 : VM_NOEXEC);

			if(!vmm_reserve_address((void *) aligned_address, pages, VM_TYPE_REGULAR, prot))
			{
				free(phdrs);
				return errno = EINVAL, NULL;
			}

			/* Note that things are mapped VM_WRITE | VM_USER before the memcpy so 
			 we don't PF ourselves(i.e: writing to RO memory) */
			
			vmm_map_range((void *) aligned_address, pages, VM_WRITE | VM_USER);
			
			/* Read the program segment to memory */
			read_vfs(0, phdrs[i].p_offset, phdrs[i].p_filesz, 
				(void*) phdrs[i].p_vaddr, args->file);

			vmm_change_perms((void *) aligned_address, pages, prot);
		}
	}

	free(phdrs);
	return (void*) header->e_entry;
}

void *elf64_load(struct binfmt_args *args, Elf64_Ehdr *header)
{
	if(!elf64_is_valid(header))
		return errno = EINVAL, NULL;
	
	switch(header->e_type)
	{
		case ET_EXEC:
			return elf64_load_static(args, header);
		default:
			return errno = EINVAL, NULL;
	}
}

