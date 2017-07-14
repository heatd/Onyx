/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <kernel/panic.h>

#include <kernel/vfs.h>
#include <kernel/elf.h>
#include <kernel/kernelinfo.h>
#include <kernel/vmm.h>
#include <kernel/modules.h>
#include <kernel/process.h>
#include <kernel/cpu.h>
#include <kernel/random.h>
#include <kernel/log.h>
#include <kernel/envp.h>
#include <kernel/binfmt.h>
#include <kernel/compiler.h>
#include <pthread_kernel.h>

void *elf_load(struct binfmt_args *args);
static Elf64_Shdr *strtab = NULL;
static Elf64_Shdr *symtab = NULL;
static Elf64_Shdr *shstrtab = NULL;
static inline char *elf_get_string(Elf64_Ehdr *hdr, Elf64_Word off)
{
	return (char*)hdr + strtab->sh_offset + off;
}
static inline char *elf_get_shstring(Elf64_Ehdr *hdr, Elf64_Word off)
{
	return (char*)hdr + shstrtab->sh_offset + off;
}
static inline Elf64_Sym *elf_get_sym(Elf64_Ehdr *hdr, char *symbolname)
{
	Elf64_Sym *syms = (Elf64_Sym*) ((char*) hdr + symtab->sh_offset);
	
	for(unsigned int i = 1; i < symtab->sh_size / symtab->sh_entsize; i++)
	{
		if(!strcmp(elf_get_string(hdr, syms[i].st_name), symbolname))
		{
			return &syms[i];
		}
	}
	return NULL;
}
static inline char *elf_get_reloc_str(Elf64_Ehdr *hdr, Elf64_Shdr *strsec, Elf64_Off off)
{
	return (char*)hdr + strsec->sh_offset + off;
}
uintptr_t get_kernel_sym_by_name(const char* name);
uintptr_t elf_resolve_symbol(Elf64_Ehdr *hdr, Elf64_Shdr *sections, Elf64_Shdr *target, size_t sym_idx)
{
	Elf64_Sym *symbol = (Elf64_Sym*)((char*)hdr + symtab->sh_offset);
	symbol = &symbol[sym_idx];
	Elf64_Shdr *stringtab = &sections[symtab->sh_link];

	if (symbol->st_shndx == SHN_UNDEF)
	{
		const char *name = elf_get_reloc_str(hdr, stringtab, symbol->st_name);
		uintptr_t val = get_kernel_sym_by_name(name);
		if(val)
			return val;
		else
		{
			if(ELF64_ST_BIND(symbol->st_info) & STB_WEAK)
				return 0;
			else
			{
				return 1;
			}
		}
	}
	else if(symbol->st_shndx == SHN_ABS)
		return symbol->st_value;
	else
	{
		Elf64_Shdr *tar = &sections[symbol->st_shndx];
		return (uintptr_t)hdr + symbol->st_value + tar->sh_offset;
	}
	return 1;
}
int elf_relocate_addend(Elf64_Ehdr *hdr, Elf64_Rela *rela, Elf64_Shdr *section)
{
	Elf64_Shdr *sections = (Elf64_Shdr*)((char*)hdr + hdr->e_shoff); 
	Elf64_Shdr *target_section = &sections[section->sh_info];
	uintptr_t addr = (uintptr_t)hdr + target_section->sh_offset;
	uintptr_t *p = (uintptr_t*)(addr + rela->r_offset);
	size_t sym_idx = ELF64_R_SYM(rela->r_info);
	if(sym_idx != SHN_UNDEF)
	{
		uintptr_t sym = elf_resolve_symbol(hdr, sections, target_section, sym_idx);
		switch (ELF64_R_TYPE(rela->r_info))
		{
			case R_X86_64_NONE: break;
			case R_X86_64_64:
				*p = RELOCATE_R_X86_64_64(sym, rela->r_addend);
				break;
			case R_X86_64_32S:
				*p = RELOCATE_R_X86_64_32S(sym, rela->r_addend);
				break;
			case R_X86_64_32:
				*p = RELOCATE_R_X86_64_32(sym, rela->r_addend);
				break;
			case R_X86_64_PC32:
				*p = RELOCATE_R_X86_64_PC32(sym, rela->r_addend, (uintptr_t) p);
				break;
			default:
				printf("Unsuported relocation!\n");
				return 1;
		}
	}
	return 0;
}
/* Shared version of elf_parse_program_headers*/
_Bool elf_parse_program_headers_s(void *file)
{
	Elf64_Ehdr *hdr = (Elf64_Ehdr *) file;
	Elf64_Phdr *phdrs = (Elf64_Phdr *) ((char *) file + hdr->e_phoff);
	Elf64_Shdr *sections = (Elf64_Shdr *) ((char *) file + hdr->e_shoff);
	void *base = NULL;
	size_t needed_size = 0;
	size_t last_size = 0;
	uintptr_t alignment = (uintptr_t) -1;
	for(Elf64_Half i = 0; i < hdr->e_phnum; i++)
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
	base = vmm_allocate_virt_address(0, vmm_align_size_to_pages(needed_size), 
				VM_TYPE_SHARED, VM_WRITE | VM_USER, alignment);
	printk("Allocated [%x - %x]\n", base, (uintptr_t) base + needed_size);
	hdr->e_entry += (uintptr_t) base;
	for(Elf64_Half i = 0; i < hdr->e_phnum; i++)
	{
		if(phdrs[i].p_type == PT_NULL)
			continue;
		if(phdrs[i].p_type == PT_LOAD)
		{
			phdrs[i].p_vaddr += (uintptr_t) base;
			uint64_t prot = VM_NOEXEC | VM_USER;
			if(phdrs[i].p_flags & PF_X)
				prot &= ~VM_NOEXEC;
			if(phdrs[i].p_flags & PF_W)
				prot |= VM_WRITE;
			vmm_map_range((void*) (phdrs[i].p_vaddr & 0xFFFFFFFFFFFFF000), 
				vmm_align_size_to_pages(phdrs[i].p_memsz + (phdrs[i].p_vaddr & 0xFFF)), prot);
			memcpy((void*) phdrs[i].p_vaddr, (const void*)((char*) file + phdrs[i].p_offset), 
			phdrs[i].p_filesz);
		}
	}
	for(size_t i = 0; i < hdr->e_shnum; i++)
	{
		if(sections[i].sh_type == SHT_RELA)
		{
			Elf64_Rela *r = (Elf64_Rela *)((char *) file + sections[i].sh_offset);
			for(size_t j = 0; j < sections[i].sh_size / sections[i].sh_entsize; j++)
			{
				Elf64_Rela *rela = &r[j];
				rela->r_offset += (uintptr_t) base;
				uintptr_t *addr = (uintptr_t*) rela->r_offset;
				printk("Applying relocation to %x\n", addr);
				switch(ELF64_R_TYPE(rela->r_info))
				{
					case R_X86_64_RELATIVE:
						*addr = RELOCATE_R_X86_64_RELATIVE((uintptr_t) base, rela->r_addend);
				}
			}
		}
	}
	return 0;
}
int elf_load_pie(char *path)
{
	printk("elf: loading interp %s\n", path);
	if(!path)
		return errno = EINVAL, 1;
	if(*path == '\0')
		return errno = EINVAL, 1;
	vfsnode_t *f = open_vfs(fs_root, path);
	if(!f)
	{
		perror("open_vfs");
		return -1;
	}
	char *file = malloc(f->size);
	if(!file)
	{
		perror("malloc");
		return -1;
	}
	size_t read = read_vfs(0, 0, f->size, file, f);
	if(read != f->size)
	{
		perror("read_vfs");
		free(file);
		close_vfs(f);
		free(f);
		return -1;
	}
	Elf64_Ehdr *header = (Elf64_Ehdr*) file;
	if(elf_is_valid(header) == false)
	{
		printf("elf: invalid interpreter!\n");
		free(file);
		close_vfs(f);
		free(f);
		return errno = EINVAL, -1;
	}
	elf_parse_program_headers_s(file);
	process_t *proc = get_current_process();
	char *kargv[] = {path, proc->cmd_line, NULL};
	int argc;
	char **argv = copy_argv(kargv, path, &argc);
	DISABLE_INTERRUPTS();
	process_create_thread((process_t*) proc, (thread_callback_t) header->e_entry, 0, argc, argv, NULL);
	Elf64_auxv_t *auxv = (Elf64_auxv_t *) proc->threads[0]->user_stack_bottom;
	unsigned char *scratch_space = (unsigned char *) (auxv + 37);
	for(int i = 0; i < 38; i++)
	{
		if(i != 0)
			auxv[i].a_type = i;
		if(i == 37)
			auxv[i].a_type = 0;
		switch(i)
		{
			case AT_PAGESZ:
				auxv[i].a_un.a_val = PAGE_SIZE;
				break;
			case AT_UID:
				auxv[i].a_un.a_val = proc->uid;
				break;
			case AT_GID:
				auxv[i].a_un.a_val = proc->gid;
				break;
			case AT_RANDOM:
				get_entropy((char*) scratch_space, 16);
				scratch_space += 16;
				break;
		}
	}
	registers_t *regs = (registers_t *) proc->threads[0]->kernel_stack;
	regs->rcx = (uintptr_t) auxv;
	ENABLE_INTERRUPTS();
	while(1);
	return 0;
}
int elf_parse_program_headers(void *file, struct binfmt_args *args)
{
	Elf64_Ehdr *hdr = (Elf64_Ehdr *) file;
	Elf64_Phdr *phdrs = (Elf64_Phdr *) ((char *) file + hdr->e_phoff);
	for (Elf64_Half i = 0; i < hdr->e_phnum; i++)
	{
		if (phdrs[i].p_type == PT_NULL)
			continue;
		if(phdrs[i].p_type == PT_INTERP)
		{
			printk("This program needs an interpreter!\n");
			printk("Interpreter: %s\n", (char*)file + phdrs[i].p_offset);
			args->filename = strdup((char*)file + phdrs[i].p_offset);
			close_vfs(args->file);
			free(args->file);
			args->file = open_vfs(fs_root, args->filename);
			if(!args->file)
				return -errno;
			free(args->file_signature);
			args->file_signature = malloc(100);
			if(!args->file_signature)
			{
				close_vfs(args->file);
				free(args->file);
				free(args->filename);
			}
			read_vfs(0, 0, 100, args->file_signature, args->file);
			for (Elf64_Half j = 0; j < hdr->e_phnum; j++)
			{
				if (phdrs[j].p_type == PT_LOAD)
				{
					size_t pages = phdrs[j].p_memsz / 4096;
					if (!pages || pages % 4096)
						pages++;
					printk("[%p - %u]\n", phdrs[j].p_vaddr & 0xFFFFFFFFFFFFF000, pages);
					vmm_reserve_address((void *) (phdrs[j].p_vaddr & 0xFFFFFFFFFFFFF000), pages, VM_TYPE_REGULAR, VM_WRITE | VM_USER);
				}
			}
			free(file);

			/* Read the interpreter */
			void *buffer = malloc(args->file->size);
			if(!buffer)
				return -1;
			read_vfs(0, 0, args->file->size, buffer, args->file);
			/* TODO: Handle argv and envp */
			if(!elf_is_valid((Elf64_Ehdr*) buffer))
			{
				free(buffer);
				return -1;
			}
			int ret = elf_parse_program_headers_s(buffer);
			if(ret == 0)
				ret = ELF_INTERP_MAGIC;
			free(buffer);
			((Elf64_Ehdr*) args->file_signature)->e_entry = ((Elf64_Ehdr*) buffer)->e_entry;
			return ret;
		}
		if (phdrs[i].p_type == PT_LOAD)
		{
			size_t pages = phdrs[i].p_memsz / 4096;
			if (!pages || pages % 4096)
				pages++;
			/* Sanitize the address first */
			if(vm_sanitize_address((void*)(phdrs[i].p_vaddr), pages) < 0)
				return false;
			if(!vmm_reserve_address((void *) (phdrs[i].p_vaddr & 0xFFFFFFFFFFFFF000), pages, VM_TYPE_REGULAR, VM_WRITE | VM_USER))
				return false;
			vmm_map_range((void *) (phdrs[i].p_vaddr & 0xFFFFFFFFFFFFF000), pages, VM_WRITE | VM_USER);
			memcpy((void*) phdrs[i].p_vaddr, (void *) ((char *) file + phdrs[i].p_offset),  phdrs[i].p_filesz);
		}
	}
	return true;
}

_Bool elf_is_valid(Elf64_Ehdr *header)
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

void *elf_load_old(void *file)
{
	if (!file)
		return errno = EINVAL, NULL;
	/* Check if its elf64 file is invalid */
	if (!elf_is_valid((Elf64_Ehdr *) file))
		return errno = EINVAL, NULL;
	elf_parse_program_headers(file, NULL);
	
	return (void *) ((Elf64_Ehdr *) file)->e_entry;
}
void* elf_load(struct binfmt_args *args)
{
	uint8_t *file_buf = malloc(args->file->size);
	if(!file_buf)
		return errno = ENOMEM, NULL;
	/* Read the file */
	read_vfs(0, 0, args->file->size, file_buf, args->file);
	Elf64_Ehdr *header = (Elf64_Ehdr *) file_buf;
	/* Validate the header */
	if(!elf_is_valid(header))
	{
		free(file_buf);
		return errno = EINVAL, NULL;
	}
	int i;
	process_t *current = get_current_process();
	current->mmap_base = vmm_gen_mmap_base();
	current->brk = vmm_reserve_address(vmm_gen_brk_base(), vmm_align_size_to_pages(0x2000000), VM_TYPE_REGULAR, VM_WRITE | VM_NOEXEC);
	if(header->e_type == ET_DYN)
		i = (int) elf_parse_program_headers_s((void*) header);
	else
		i = elf_parse_program_headers((void*) header, args);

	current->brk = vmm_allocate_virt_address(0, 1, VM_TYPE_HEAP, VM_WRITE | VM_NOEXEC | VM_USER, 0);
	ENABLE_INTERRUPTS();
	if(i == ELF_INTERP_MAGIC)
	{
		return (void*) ((Elf64_Ehdr*) args->file_signature)->e_entry;
	}
	return (void*) header->e_entry;
}
void *elf_load_kernel_module(void *file, void **fini_func)
{
	if (!file)
		return errno = EINVAL, NULL;
	/* Check if its elf64 file is invalid */
	Elf64_Ehdr *header = (Elf64_Ehdr*) file;
	if (!elf_is_valid(header))
		return errno = EINVAL, NULL;
	Elf64_Shdr *sections = (Elf64_Shdr*)((char*)file + header->e_shoff);
	shstrtab = &sections[header->e_shstrndx];
	for(size_t i = 0; i < header->e_shnum; i++)
	{
		if(!strcmp(elf_get_shstring(header, sections[i].sh_name), ".symtab"))
			symtab = &sections[i];
		if(!strcmp(elf_get_shstring(header, sections[i].sh_name), ".strtab"))
			strtab = &sections[i];
	}
	_Bool modinfo_found = 0;
	for(size_t i = 0; i < header->e_shnum; i++)
	{
			if(!strcmp(elf_get_shstring(header, sections[i].sh_name), ".modinfo"))
			{
				modinfo_found = 1;

				char *parse = (char*) file + sections[i].sh_offset;
				char *kver = NULL;
				for(size_t j = 0; j < sections[i].sh_size; j++)
				{
					if(*parse != 'k' && *(parse+1) != 'e' && *(parse+2) != 'r' && *(parse+3) != 'n' && *(parse+4) != 'e' && *(parse+5) != 'l' && *(parse+6) != '=')
					{
						kver = parse + strlen("kernel=") - 1;
						break;
					}
					parse++;
				}
				if(!kver)
					return NULL;
				/* Check if the kernel version matches up */
				if(strcmp(OS_RELEASE, kver))
				{
					FATAL("module", "Kernel version does not match with the module!\n");
					return NULL;
				}
			}
	}
	if(!modinfo_found)
		return NULL;	
	uintptr_t first_address = 0;
	for(size_t i = 0; i < header->e_shnum; i++)
	{
		if(sections[i].sh_flags & SHF_ALLOC) 
		{
			void *mem = allocate_module_memory(sections[i].sh_size);
			if(i == 1) first_address = (uintptr_t) mem;
			if(sections[i].sh_type == SHT_NOBITS)
				memset(mem, 0, sections[i].sh_size);
			else
				memcpy(mem, (char*) file + sections[i].sh_offset, sections[i].sh_size);
			sections[i].sh_offset = (Elf64_Off) mem - (Elf64_Off) header;
		}
	}
	for(size_t i = 0; i < header->e_shnum; i++)
	{
		if(sections[i].sh_type == SHT_RELA)
		{
			Elf64_Rela *r = (Elf64_Rela*)((char*)file + sections[i].sh_offset);
			for(size_t j = 0; j < sections[i].sh_size / sections[i].sh_entsize; j++)
			{
				Elf64_Rela *rela = &r[j];
				if(elf_relocate_addend(header, rela, &sections[i]) == 1)
				{
					printf("Couldn't relocate the kernel module!\n");
					return errno = EINVAL, NULL;
				}
			}
		}
	}
	Elf64_Sym *init_sym = (Elf64_Sym*)((uintptr_t) elf_get_sym(header, "module_init"));
	void *sym = (void*)(init_sym->st_value + first_address);
	init_sym = (Elf64_Sym*)((uintptr_t) elf_get_sym(header, "module_fini"));
	void *fini = (void*)(init_sym->st_value + first_address);
	*fini_func = fini;
	return sym;
}
struct binfmt elf_binfmt = {
	.signature = (unsigned char *)"\x7f""ELF",
	.size_signature = 4,
	.callback = elf_load,
	.next = NULL
};
__init void __elf_init()
{
	install_binfmt(&elf_binfmt);
}
