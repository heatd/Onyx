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
#include <kernel/elf.h>
#include <kernel/vmm.h>
#include <stdbool.h>

_Bool elf_parse_program_headers(void *file)
{
	Elf64_Ehdr *hdr = (Elf64_Ehdr *) file;
	Elf64_Phdr *phdrs = (Elf64_Phdr *) ((char *) file + hdr->e_phoff);
	for (Elf64_Half i = 0; i < hdr->e_phnum; i++) {
		if (phdrs[i].p_type == PT_NULL)
			continue;
		if (phdrs[i].p_type == PT_LOAD) {
			size_t pages = phdrs[i].p_memsz / 4096;
			if (!pages || pages % 4096)
				pages++;
			void *mem =
			    vmm_map_range((void *) (phdrs[i].p_vaddr &
						    0xFFFFFFFFFFFFF000),
					  pages, VMM_WRITE | VMM_USER);
			    vmm_reserve_address((void *) (phdrs[i].p_vaddr &
						    0xFFFFFFFFFFFFF000), pages, VMM_TYPE_REGULAR, VMM_WRITE | VMM_USER);
			memcpy(mem,
			       (void *) ((char *) file +
					 phdrs[i].p_offset),
			       phdrs[i].p_filesz);
		}
	}
	return true;
}

_Bool elf_is_valid(Elf64_Ehdr * header)
{
	if (memcmp(&header->e_ident, ELF_MAGIC, 4))
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

void *elf_load(void *file)
{
	if (!file)
		return errno = EINVAL, NULL;
	/* Check if its elf64 file is invalid */
	if (!elf_is_valid((Elf64_Ehdr *) file))
		return errno = EINVAL, NULL;
	elf_parse_program_headers(file);
	return (void *) ((Elf64_Ehdr *) file)->e_entry;
}
