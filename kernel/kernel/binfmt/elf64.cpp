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
#include <onyx/vfs.h>
#include <onyx/exec.h>

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

/* FIXME: Unify load static and load dyn */
void *elf64_load_static(struct binfmt_args *args, Elf64_Ehdr *header)
{
	struct process *current = get_current_process();
	bool is_interp = args->needs_interp;
	size_t program_headers_size = header->e_phnum * header->e_phentsize;
	Elf64_Phdr *phdrs = (Elf64_Phdr *) malloc(program_headers_size);
	if(!phdrs)
		return errno = ENOMEM, nullptr;

	/* Read the program header */

	read_vfs(header->e_phoff, program_headers_size, phdrs, args->file);

	struct file *fd = args->file;

	Elf64_Dyn *dyn = nullptr;
	Elf64_Phdr *uphdrs = nullptr;
	bool load_addr_set = false;
	unsigned long load_addr = 0;

	int st;
	if((st = flush_old_exec(args->state)) < 0)
	{
		errno = -st;
		return nullptr;
	}

	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if(phdrs[i].p_type == PT_NULL)
			continue;
		if(phdrs[i].p_type == PT_INTERP)
		{
			/* We allocate one more byte for the nullptr byte so we don't get buffer overflow'd */
			args->interp_path = (char *) malloc(phdrs[i].p_filesz + 1);
			if(!args->interp_path)
				return errno = ENOMEM, nullptr;
			args->interp_path[phdrs[i].p_filesz] = '\0';

			read_vfs(phdrs[i].p_offset, phdrs[i].p_filesz,
				 args->interp_path, args->file);
			args->needs_interp = true;
		}

		if(phdrs[i].p_type == PT_DYNAMIC)
		{
			dyn = (Elf64_Dyn *) (phdrs[i].p_vaddr);
		}

		if(phdrs[i].p_type == PT_PHDR)
		{
			uphdrs = (Elf64_Phdr *) (phdrs[i].p_vaddr);
		}

		if(phdrs[i].p_type == PT_LOAD)
		{
			uintptr_t aligned_address = phdrs[i].p_vaddr & ~(PAGE_SIZE - 1);
			size_t misalignment = phdrs[i].p_vaddr - aligned_address;
			size_t total_size = phdrs[i].p_memsz + (phdrs[i].p_vaddr - aligned_address);
			size_t pages = total_size / PAGE_SIZE;
			if(total_size % PAGE_SIZE)
				pages++;

			/* Sanitize the address first */
			if(vm_sanitize_address((void*) aligned_address, pages) < 0)
			{
				free(phdrs);
				return errno = EINVAL, nullptr;
			}

			int prot = ((phdrs[i].p_flags & PF_R) ? PROT_READ : 0) |
				   ((phdrs[i].p_flags & PF_W) ? PROT_WRITE : 0) |
				   ((phdrs[i].p_flags & PF_X) ? PROT_EXEC : 0);
			if(!vm_mmap((void *) aligned_address, pages << PAGE_SHIFT, prot, MAP_PRIVATE | MAP_FIXED, 
			            fd, phdrs[i].p_offset - misalignment))
			{
				errno = ENOMEM;
				return nullptr;
			}

			if(phdrs[i].p_filesz != phdrs[i].p_memsz)
			{
				if(!(prot & PROT_WRITE))
				{
					errno = ENOEXEC;
					return nullptr;
				}

				/* This program header has the .bss, zero it out */
				uint8_t *bss_base = (uint8_t *) (phdrs[i].p_vaddr + phdrs[i].p_filesz);
				uint8_t *zero_pages_base = (uint8_t *) page_align_up(bss_base);
				size_t bss_size = phdrs[i].p_memsz - phdrs[i].p_filesz;
				size_t to_zero = zero_pages_base - bss_base;
				if(to_zero > bss_size)
					to_zero = bss_size;

				size_t zero_pages_len = bss_size - to_zero;

				if(zero_pages_len)
				{
					size_t zero_pages = zero_pages_len / PAGE_SIZE;
					if(zero_pages_len % PAGE_SIZE)
						zero_pages++;

					if(!vm_mmap(zero_pages_base, zero_pages << PAGE_SHIFT, prot,
						MAP_PRIVATE | MAP_FIXED | MAP_ANON, nullptr, 0))
					{
						errno = ENOMEM;
						return nullptr;
					}
				}

				if(to_zero)
				{
					if(user_memset(bss_base, 0, bss_size) < 0)
					{
						errno = EFAULT;
						return nullptr;
					}
				}
			}

			if(!load_addr_set)
			{
				load_addr = phdrs[i].p_vaddr - phdrs[i].p_offset;
				load_addr_set = true;
			}
		}
	}

	if(!is_interp)
	{
		current->info.phent = header->e_phentsize;
		current->info.phnum = header->e_phnum;
		if(!uphdrs)
		{
			uphdrs = (Elf64_Phdr *) (load_addr + header->e_phoff);
		}

		current->info.phdr = uphdrs;
		current->info.dyn = dyn;
		current->info.program_entry = (void *) header->e_entry;
	}
	else
	{
		current->info.dyn = dyn;
	}

	free(phdrs);
	return (void*) header->e_entry;
}

size_t elf_calculate_map_size(Elf64_Phdr *phdrs, size_t num)
{
	/* Took this idea from linux :) */

	size_t first_load = -1, last_load = -1;
	for(size_t i = 0; i < num; i++)
	{
		if(phdrs[i].p_type == PT_LOAD)
		{
			last_load = i;

			if(first_load == (size_t) -1)
				first_load = i;
		}
	}

	if(first_load == (size_t) -1)
		return -1;

	return (phdrs[last_load].p_vaddr + phdrs[last_load].p_memsz)
		- (unsigned long) page_align_up((void *) phdrs[first_load].p_vaddr);
}

void *elf64_load_dyn(struct binfmt_args *args, Elf64_Ehdr *header)
{
	bool is_interp = args->needs_interp;

	struct process *current = get_current_process();
	size_t program_headers_size = header->e_phnum * header->e_phentsize;
	struct file *fd = args->file;
	void *base = nullptr;
	Elf64_Dyn *dyn = nullptr;
	Elf64_Phdr *uphdrs = nullptr;
	size_t needed_size = 0;

	int st = 0;

	Elf64_Phdr *phdrs = (Elf64_Phdr *) malloc(program_headers_size);
	if(!phdrs)
	{
		errno = ENOMEM;
		goto error0;
	}

	/* Read the program headers */
	if(read_vfs(header->e_phoff, program_headers_size, phdrs, args->file) !=
		(ssize_t) program_headers_size)
	{
		errno = EIO;
		goto error1;
	}

	if((st = flush_old_exec(args->state)) < 0)
	{
		errno = -st;
		goto error1;
	}

	needed_size = elf_calculate_map_size(phdrs, header->e_phnum);

	if(needed_size == (size_t) -1)
	{
		errno = ENOEXEC;
		goto error1;
	}

	base = vm_mmap(nullptr, vm_size_to_pages(needed_size) << PAGE_SHIFT, PROT_NONE,
	               MAP_ANONYMOUS | MAP_PRIVATE, nullptr, 0);
	if(!base)
	{
		errno = ENOMEM;
		goto error1;
	}

	//printk("initial mmap %p to %p\n", base, (void *)((unsigned long) base + (vm_size_to_pages(needed_size) << PAGE_SHIFT)));

	header->e_entry += (uintptr_t) base;

	for(Elf64_Half i = 0; i < header->e_phnum; i++)
	{
		if(phdrs[i].p_type == PT_NULL)
			continue;

		if(phdrs[i].p_type == PT_INTERP)
		{
			/* The interpreter can't have an interpreter of its own */
			if(is_interp)
				return errno = ENOEXEC, nullptr;

			/* We allocate one more byte for the nullptr byte so we don't get buffer overflow'd */
			args->interp_path = (char *) malloc(phdrs[i].p_filesz + 1);
			if(!args->interp_path)
				return errno = ENOMEM, nullptr;
			args->interp_path[phdrs[i].p_filesz] = '\0';

			read_vfs(phdrs[i].p_offset, phdrs[i].p_filesz,
				 args->interp_path, args->file);
			args->needs_interp = true;
		}

		if(phdrs[i].p_type == PT_DYNAMIC)
		{
			dyn = (Elf64_Dyn *) (phdrs[i].p_vaddr + (uintptr_t) base);
		}

		if(phdrs[i].p_type == PT_PHDR)
		{
			uphdrs = (Elf64_Phdr *) (phdrs[i].p_vaddr + (uintptr_t) base);
		}

		if(phdrs[i].p_type == PT_LOAD)
		{
			phdrs[i].p_vaddr += (uintptr_t) base;
			uintptr_t aligned_address = phdrs[i].p_vaddr & ~(PAGE_SIZE - 1);
			size_t total_size = phdrs[i].p_memsz + (phdrs[i].p_vaddr - aligned_address);
			size_t pages = vm_size_to_pages(total_size);
			size_t misalignment = phdrs[i].p_vaddr - aligned_address;
		
			/* Sanitize the address first */
			if(vm_sanitize_address((void*) aligned_address, pages) < 0)
			{
				errno = EINVAL;
				goto error2;
			}

			int prot = ((phdrs[i].p_flags & PF_R) ? PROT_READ : 0) |
				   ((phdrs[i].p_flags & PF_W) ? PROT_WRITE : 0) |
				   ((phdrs[i].p_flags & PF_X) ? PROT_EXEC : 0);

			//printk("mmaping [%lx, %lx]\n", aligned_address, aligned_address + (pages << PAGE_SHIFT));
			if(!vm_mmap((void *) aligned_address, pages << PAGE_SHIFT, prot, MAP_PRIVATE | MAP_FIXED,
			            fd, phdrs[i].p_offset - misalignment))
			{
				perror("create file mapping");
				errno = ENOMEM;
				goto error2;
			}

			if(phdrs[i].p_filesz != phdrs[i].p_memsz)
			{
				if(!(prot & PROT_WRITE))
				{
					/* This malicious binary is trying to get us to segfault by writing to 
					 * read-only memory
					 */
					errno = ENOEXEC;
					goto error2;
				}

				uint8_t *bss_base = (uint8_t *) (phdrs[i].p_vaddr + phdrs[i].p_filesz);
				uint8_t *zero_pages_base = (uint8_t *) page_align_up(bss_base);
				size_t bss_size = phdrs[i].p_memsz - phdrs[i].p_filesz;
				size_t to_zero = zero_pages_base - bss_base;
				if(to_zero > bss_size)
					to_zero = bss_size;

				size_t zero_pages_len = bss_size - to_zero;

				if(zero_pages_len)
				{
					size_t zero_pages = zero_pages_len / PAGE_SIZE;
					if(zero_pages_len % PAGE_SIZE)
						zero_pages++;

					if(!vm_mmap(zero_pages_base, zero_pages << PAGE_SHIFT, prot,
						MAP_PRIVATE | MAP_FIXED | MAP_ANON, nullptr, 0))
					{
						errno = ENOMEM;
						return nullptr;
					}
				}

				if(to_zero)
				{
					if(user_memset(bss_base, 0, bss_size) < 0)
					{
						errno = EFAULT;
						return nullptr;
					}
				}
			}
		}
	}

	free(phdrs);
	phdrs = nullptr;

	if(is_interp) current->interp_base = (void*) base;
	else
		current->image_base = (void *) base;

	if(!is_interp)
	{
		current->info.phent = header->e_phentsize;
		current->info.phnum = header->e_phnum;
		current->info.phdr = uphdrs;
		current->info.dyn = dyn;
		current->info.program_entry = (void *) header->e_entry;
		//printk("phdrs: %p\n", current->info.phdr);
	}
	else
	{
		current->info.dyn = dyn;
	}

	/* TODO: Unmap holes */

	return (void*) header->e_entry;
error2:
	vm_munmap(get_current_address_space(), base, needed_size);
error1:
	free(phdrs);
error0:
	return nullptr;
}

void *elf64_load(struct binfmt_args *args, Elf64_Ehdr *header)
{
	if(!elf64_is_valid(header))
		return errno = EINVAL, nullptr;
	
	switch(header->e_type)
	{
		case ET_EXEC:
			return elf64_load_static(args, header);
		case ET_DYN:
			return elf64_load_dyn(args, header);
		default:
			return errno = EINVAL, nullptr;
	}
}

