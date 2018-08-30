/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <errno.h>
#include <stdio.h>

#include <onyx/process.h>
#include <onyx/binfmt/elf64.h>
#include <onyx/vm.h>

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

	struct file_description *fd = create_file_description(args->file, 0);
	if(!fd)
	{
		free(phdrs);
		return NULL;
	}

	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if(phdrs[i].p_type == PT_NULL)
			continue;
		if(phdrs[i].p_type == PT_INTERP)
		{
			args->interp_path = malloc(phdrs[i].p_filesz);
			if(!args->interp_path)
				return errno = ENOMEM, NULL;
			read_vfs(0, phdrs[i].p_offset, phdrs[i].p_filesz,
				 args->interp_path, args->file);
			args->needs_interp = true;
		}

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
			if(phdrs[i].p_memsz > phdrs[i].p_filesz)
			{
				if(!map_user((void *) aligned_address, pages,
					VM_TYPE_REGULAR, prot))
				{
					free(phdrs);
					return errno = ENOMEM, NULL;
				}
				read_vfs(0, phdrs[i].p_offset, phdrs[i].p_filesz,
					(void *) phdrs[i].p_vaddr, fd->vfs_node);
			}
			else
			{
				int flags = VM_MMAP_PRIVATE | VM_MMAP_FIXED;

				void *mem = create_file_mapping((void *) aligned_address,
					pages, flags, prot, fd, phdrs[i].p_offset & -PAGE_SIZE);
				if(!mem)
				{
					free(phdrs);
					return errno = EINVAL, NULL;
				}
			}
		}
	}

	void *map = get_user_pages(VM_TYPE_REGULAR,
		vm_align_size_to_pages(program_headers_size), VM_WRITE | VM_NOEXEC);
	if(!map)
		return NULL;
	
	memcpy(map, phdrs, program_headers_size);
	struct process *p = get_current_process();
	p->info.phdr = map;
	p->info.phent = header->e_phentsize;
	p->info.phnum = header->e_phnum;

	free(phdrs);
	return (void*) header->e_entry;
}

void *elf64_load_dyn(struct binfmt_args *args, Elf64_Ehdr *header)
{
	struct process *current = get_current_process();
	size_t program_headers_size = header->e_phnum * header->e_phentsize;
	Elf64_Phdr *phdrs = malloc(program_headers_size);
	if(!phdrs)
		return errno = ENOMEM, NULL;
	/* Read the program header */

	read_vfs(0, header->e_phoff, program_headers_size, phdrs, args->file);

	void *base = NULL;
	size_t needed_size = 0;
	size_t last_size = 0;
	uintptr_t alignment = (uintptr_t) -1;
	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if(phdrs[i].p_type == PT_NULL)
			continue;
		if(phdrs[i].p_type == PT_LOAD)
		{
			needed_size += phdrs[i].p_vaddr;
			last_size = phdrs[i].p_memsz;
			if(alignment == (uintptr_t) -1)
				alignment = phdrs[i].p_align;
		}
	}
	needed_size += last_size;
	base = get_pages(VM_ADDRESS_USER, VM_TYPE_SHARED, vm_align_size_to_pages(needed_size), 
				VM_WRITE | VM_USER, alignment);
	if(!base)
		return NULL;
	header->e_entry += (uintptr_t) base;
	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if(phdrs[i].p_type == PT_NULL)
			continue;
		if(phdrs[i].p_type == PT_LOAD)
		{
			phdrs[i].p_vaddr += (uintptr_t) base;
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

			/* Note that things are mapped VM_WRITE | VM_USER before the memcpy so 
			 we don't PF ourselves(i.e: writing to RO memory) */
			
			vm_map_range((void *) aligned_address, pages, VM_WRITE | VM_USER);
			
			/* Read the program segment to memory */
			read_vfs(0, phdrs[i].p_offset, phdrs[i].p_filesz, 
				(void*) phdrs[i].p_vaddr, args->file);

			vm_change_perms((void *) aligned_address, pages, prot);
		}
	}

	void *ptr = get_user_pages(VM_TYPE_REGULAR,
			vm_align_size_to_pages(program_headers_size), VM_WRITE | VM_NOEXEC);
	if(!ptr)
		return NULL;

	memcpy(ptr, phdrs, program_headers_size);
	free(phdrs);
	size_t sections_size = header->e_shnum * header->e_shentsize;
	Elf64_Shdr *sections = malloc(sections_size);
	if(!sections)
		return NULL;
	
	read_vfs(0, header->e_shoff, sections_size, sections, args->file);

	for(size_t i = 0; i < header->e_shnum; i++)
	{
		if(sections[i].sh_type == SHT_RELA)
		{
			Elf64_Rela *r = malloc(sections[i].sh_size);
			if(!r)
			{
				free(sections);
				return NULL;
			}

			read_vfs(0, sections[i].sh_offset, sections[i].sh_size, r, args->file);

			for(size_t j = 0; j < sections[i].sh_size / sections[i].sh_entsize; j++)
			{
				Elf64_Rela *rela = &r[j];
				rela->r_offset += (uintptr_t) base;
				uintptr_t *addr = (uintptr_t*) rela->r_offset;
				switch(ELF64_R_TYPE(rela->r_info))
				{
					case R_X86_64_RELATIVE:
						*addr =
						RELOCATE_R_X86_64_RELATIVE(
							(uintptr_t) base,
							rela->r_addend);
				}
			}
			free(r);
		}
	}

	current->image_base = (void*) base;
	current->info.phent = header->e_phentsize;
	current->info.phnum = header->e_phnum;
	current->info.phdr = ptr;

	for(size_t i = 0; i < header->e_phnum; i++)
	{
		if(current->info.phdr[i].p_type == PT_DYNAMIC)
		{
			void *dyn = get_user_pages(VM_TYPE_REGULAR,
				vm_align_size_to_pages(current->info.phdr[i].p_filesz),
				VM_WRITE | VM_NOEXEC);
			if(!dyn)
				return NULL;
			read_vfs(0, current->info.phdr[i].p_offset,
				current->info.phdr[i].p_filesz, dyn, args->file);
			current->info.phdr[i].p_vaddr = (uintptr_t) dyn;
		}
	}
	free(sections);
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
		case ET_DYN:
			return elf64_load_dyn(args, header);
		default:
			return errno = EINVAL, NULL;
	}
}

