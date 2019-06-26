/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <onyx/panic.h>

#include <onyx/vfs.h>
#include <onyx/elf.h>
#include <onyx/kernelinfo.h>
#include <onyx/vm.h>
#include <onyx/modules.h>
#include <onyx/process.h>
#include <onyx/cpu.h>
#include <onyx/random.h>
#include <onyx/log.h>
#include <onyx/binfmt.h>
#include <onyx/compiler.h>
#include <onyx/binfmt/elf64.h>
#include <onyx/symbol.h>
#include <onyx/fnv.h>

#include <pthread_kernel.h>

void *elf_load(struct binfmt_args *args);

struct elf_loader_context
{
	Elf64_Ehdr *header;
	Elf64_Shdr *sections;
	Elf64_Shdr *shstrtab;
	Elf64_Shdr *symtab;
	Elf64_Shdr *strtab;
	Elf64_Sym *syms;
};

static inline char *elf_get_string(struct elf_loader_context *context, Elf64_Word off)
{
	return (char*) context->header + context->strtab->sh_offset + off;
}

static inline char *elf_get_shstring(struct elf_loader_context *context, Elf64_Word off)
{
	return (char*) context->header + context->shstrtab->sh_offset + off;
}

static Elf64_Sym *elf_get_sym(struct elf_loader_context *ctx, char *symname)
{
	Elf64_Sym *syms = ctx->syms;
	size_t nr_entries = ctx->symtab->sh_size / ctx->symtab->sh_entsize;
	
	for(unsigned int i = 1; i < nr_entries; i++)
	{
		if(!strcmp(elf_get_string(ctx,  syms[i].st_name), symname))
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

uintptr_t get_common_block(const char *name, size_t size);

uintptr_t elf_resolve_symbol(struct elf_loader_context *ctx, Elf64_Shdr *target, size_t sym_idx)
{
	Elf64_Sym *symbol = &ctx->syms[sym_idx];
	Elf64_Shdr *stringtab = &ctx->sections[ctx->symtab->sh_link];

	if(symbol->st_shndx == SHN_UNDEF)
	{
		const char *name = elf_get_reloc_str(ctx->header, stringtab, symbol->st_name);
		uintptr_t val = module_resolve_sym(name);

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
	else if(symbol->st_shndx == SHN_COMMON)
	{
		const char *name = elf_get_reloc_str(ctx->header, stringtab, symbol->st_name);
		assert(symbol->st_value <= PAGE_SIZE);
		return get_common_block(name, symbol->st_size);
	}
	else
	{
		Elf64_Shdr *tar = &ctx->sections[symbol->st_shndx];
		return (uintptr_t) ctx->header + symbol->st_value + tar->sh_offset;
	}

	return 1;
}

__attribute__((no_sanitize_undefined))
int elf_relocate_addend(struct elf_loader_context *ctx, Elf64_Rela *rela, Elf64_Shdr *section)
{
	Elf64_Shdr *sections = ctx->sections;
	Elf64_Shdr *target_section = &sections[section->sh_info];
	//printk("Section index: %lu\n", section->sh_info);
	uintptr_t addr =  (uintptr_t)((char *) ctx->header + target_section->sh_offset);
	//printk("Addr: %lx\n", addr);
	uintptr_t *p = (uintptr_t*) (addr + rela->r_offset);
	//printk("P: %p\n", p);
	size_t sym_idx = ELF64_R_SYM(rela->r_info);

	int32_t *ptr32s = (int32_t*) p;
	uint32_t *ptr32u = (uint32_t *) p;
	if(sym_idx != SHN_UNDEF)
	{
		uintptr_t sym = elf_resolve_symbol(ctx, target_section, sym_idx);

		switch (ELF64_R_TYPE(rela->r_info))
		{
			case R_X86_64_NONE: break;
			case R_X86_64_64:
				*p = RELOCATE_R_X86_64_64(sym, rela->r_addend);
				break;
			case R_X86_64_32S:
				*ptr32s = RELOCATE_R_X86_64_32S(sym, rela->r_addend);
				break;
			case R_X86_64_32:
				*ptr32u = RELOCATE_R_X86_64_32(sym, rela->r_addend);
				break;
			case R_X86_64_PC32:
				*ptr32u = RELOCATE_R_X86_64_PC32(sym, rela->r_addend, (uintptr_t) p);
				break;
			default:
				printk("Unsuported relocation!\n");
				return 1;
		}
	}
	return 0;
}

bool elf_is_valid(Elf64_Ehdr *header)
{
	if(header->e_ident[EI_MAG0] != 0x7F ||
	   header->e_ident[EI_MAG1] != 'E' ||
	   header->e_ident[EI_MAG2] != 'L' ||
	   header->e_ident[EI_MAG3] != 'F')
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

void* elf_load(struct binfmt_args *args)
{
	Elf64_Ehdr *header = malloc(sizeof(Elf64_Ehdr));
	if(!header)
		return errno = EINVAL, NULL;
	read_vfs(0, 0, sizeof(Elf64_Ehdr), header, args->file);

	void *entry = NULL;
	switch(header->e_ident[EI_CLASS])
	{
		case ELFCLASS32:
			free(header);
			/* TODO: Add an elf32 loader */
			return errno = EINVAL, NULL;
		case ELFCLASS64:
			entry = elf64_load(args, header);
			break;
	}
	
	free(header);
	
	if(args->needs_interp)
		entry = bin_do_interp(args);

	return entry;
}

bool elf_validate_modinfo(struct elf_loader_context *ctx)
{
	bool modinfo_found = false;

	const size_t shnum = ctx->header->e_shnum;

	for(size_t i = 0; i < shnum; i++)
	{
		Elf64_Shdr *section = &ctx->sections[i];

		if(!strcmp(elf_get_shstring(ctx,section->sh_name), ".modinfo"))
		{
			modinfo_found = true;

			char *parse = (char*) ctx->header + section->sh_offset;
			char *kver = NULL;
			for(size_t j = 0; j < section->sh_size; j++)
			{
				if(strncmp(parse, "kernel=", strlen("kernel=")) != 0)
				{
					kver = parse + strlen("kernel=") - 1;
					break;
				}
				parse++;
			}

			if(!kver)
				return false;

			/* Check if the kernel version matches up */
			if(strcmp(OS_RELEASE, kver))
			{
				FATAL("module", "Kernel version does not match with the module!\n");
				return false;
			}
		}
	}

	return modinfo_found;
}

#define ALIGN(x, n) ((x + n-1) & -n)

static inline bool is_text_section(Elf64_Shdr *section)
{
	bool is_write = section->sh_flags & SHF_WRITE;
	bool is_exec = section->sh_flags & SHF_EXECINSTR;
	return (!is_write && is_exec);
}

static inline bool is_data_section(Elf64_Shdr *section)
{
	bool is_write = section->sh_flags & SHF_WRITE;
	bool is_exec = section->sh_flags & SHF_EXECINSTR;
	return (is_write && !is_exec);
}

static inline bool is_ro_section(Elf64_Shdr *section)
{
	bool is_write = section->sh_flags & SHF_WRITE;
	bool is_exec = section->sh_flags & SHF_EXECINSTR;
	return (!is_write && !is_exec);
}

void elf_create_module_layout(struct elf_loader_context *ctx, struct module *module)
{
	struct module_layout *layout = &module->layout;
	for(size_t i = 0; i < ctx->header->e_shnum; i++)
	{
		Elf64_Shdr *section = &ctx->sections[i];

		if(!(section->sh_flags & SHF_ALLOC))
			continue;

		if(is_text_section(section))
		{
			layout->text_size = ALIGN(layout->text_size, section->sh_addralign);
			layout->text_size += section->sh_size;
		}
		else if(is_data_section(section))
		{
			layout->data_size = ALIGN(layout->data_size, section->sh_addralign);
			layout->data_size += section->sh_size;
		}
		else if(is_ro_section(section))
		{
			layout->ro_size = ALIGN(layout->ro_size, section->sh_addralign);
			layout->ro_size += section->sh_size;
		}
	}
#if DEBUG_MODULES
	printk("Text size: %lx\nData size: %lx\nRo size: %lx\n",
		layout->text_size, layout->data_size, layout->ro_size);
#endif
}

#define ELF_MODULE_TEXT		0
#define ELF_MODULE_RO		1
#define ELF_MODULE_DATA		2

const int module_prots[] =
{
	0,
	VM_NOEXEC,
	VM_WRITE | VM_NOEXEC
};

bool elf_load_module_sections(struct elf_loader_context *ctx, struct module *module, int type)
{
	bool (*section_checker[])(Elf64_Shdr *shdr) = 
	{
		is_text_section,
		is_ro_section,
		is_data_section
	};

	size_t region_size;
	/* This points to the start_* that we need to fill */
	unsigned long *addr_p = NULL;
	if(type == ELF_MODULE_TEXT)
	{
		region_size = module->layout.text_size;
		addr_p = &module->layout.start_text;
	}
	else if(type == ELF_MODULE_RO)
	{
		region_size = module->layout.ro_size;
		addr_p = &module->layout.start_ro;
	}
	else if(type == ELF_MODULE_DATA)
	{
		region_size = module->layout.data_size;
		addr_p = &module->layout.start_data;
	}
	else
	{
		panic("bad type argument");
	}


	void *mem = module_allocate_pages(region_size, module_prots[type]);
	if(!mem)
		return false;

	*addr_p = (unsigned long) mem;

	/* Enable write, we'll fix this up in a moment */
	vm_change_perms(mem, vm_align_size_to_pages(region_size), VM_WRITE);

	unsigned long addr = *addr_p;
	for(size_t i = 0; i < ctx->header->e_shnum; i++)
	{
		Elf64_Shdr *section = &ctx->sections[i];
		if(section->sh_flags & SHF_ALLOC &&
		   section_checker[type](section)) 
		{
			addr = ALIGN(addr, section->sh_addralign);

			section->sh_addr = addr;
	
			if(section->sh_type == SHT_NOBITS)
			{
				/* module_allocate_pages returns zero'd memory,
				 * so don't bother to zero it out */
				/* memset(mem, 0, section->sh_size); */
			}
			else
			{
				memcpy((void *) addr, (char*) ctx->header +
					section->sh_offset, section->sh_size);
			}

			section->sh_offset = (Elf64_Off) addr - (Elf64_Off) ctx->header;

			addr += section->sh_size;
		}
	}

	return true;
}

void elf_restore_module_perms(struct module *module)
{
	vm_change_perms((void *) module->layout.start_text,
		vm_align_size_to_pages(module->layout.text_size), module_prots[ELF_MODULE_TEXT]);

	vm_change_perms((void *) module->layout.start_ro,
		vm_align_size_to_pages(module->layout.ro_size), module_prots[ELF_MODULE_RO]);
	
	vm_change_perms((void *) module->layout.start_data,
		vm_align_size_to_pages(module->layout.data_size), module_prots[ELF_MODULE_DATA]);
}

bool elf_setup_symtable(struct elf_loader_context *ctx, struct module *module)
{
	const size_t nr_entries = ctx->symtab->sh_size / ctx->symtab->sh_entsize;
	Elf64_Sym *symtab = (void *)((char *) ctx->header + ctx->symtab->sh_offset);

	size_t nr_symbols = 0;

	for(size_t i = 0; i < nr_entries; i++)
	{
		Elf64_Sym *sym = &symtab[i];

		if(is_useful_symbol(sym))
			nr_symbols++;
	}

	struct symbol *symbol_table = zalloc(sizeof(struct symbol) * nr_symbols);
	if(!symbol_table)
		return false;

	for(size_t i = 0, n = 0; i < nr_entries; i++)
	{
		Elf64_Sym *sym = &symtab[i];
		Elf64_Shdr *section = &ctx->sections[sym->st_shndx];

		if(!is_useful_symbol(sym))
			continue;

		const char *name = elf_get_string(ctx, sym->st_name);

		struct symbol *s = &symbol_table[n];
		
		unsigned long base = section->sh_addr;

		sym->st_value += base;

		if(setup_symbol(s, sym, name) < 0)
			goto fail;
		n++;
	}

	module->symtable = symbol_table;
	module->nr_symtable_entries = nr_symbols;

	return true;
fail:
	for(size_t i = 0; i < nr_symbols; i++)
	{
		if(!symbol_table[i].name)
			break;
		free(symbol_table[i].name);
	}

	free(symbol_table);
	return false;
}

void *elf_load_kernel_module(void *file, struct module *module)
{
	struct elf_loader_context ctx = {};

	if(!file)
		return errno = EINVAL, NULL;
	
	/* Check if its elf64 file is invalid */
	Elf64_Ehdr *header = (Elf64_Ehdr*) file;
	if(!elf_is_valid(header))
		return errno = EINVAL, NULL;
	
	ctx.header = header;
	Elf64_Shdr *sections = (Elf64_Shdr*)((char*) file + header->e_shoff);
	
	ctx.sections = sections;
	ctx.shstrtab = &sections[header->e_shstrndx];

	Elf64_Shdr *symtab = NULL, *strtab = NULL;

	for(size_t i = 0; i < header->e_shnum; i++)
	{
		if(!strcmp(elf_get_shstring(&ctx, sections[i].sh_name), ".symtab"))
			symtab = &sections[i];
		if(!strcmp(elf_get_shstring(&ctx, sections[i].sh_name), ".strtab"))
			strtab = &sections[i];
	}

	if(!symtab)
		return errno = EINVAL, NULL;
	if(!strtab)
		return errno = EINVAL, NULL;
	
	ctx.strtab = strtab;
	ctx.symtab = symtab;
	ctx.syms = (Elf64_Sym *)((char *) file + symtab->sh_offset);

	bool modinfo_valid = elf_validate_modinfo(&ctx);

	if(!modinfo_valid)
		return errno = EINVAL, NULL;
	
	elf_create_module_layout(&ctx, module);

	if(!elf_load_module_sections(&ctx, module, ELF_MODULE_TEXT) ||
	   !elf_load_module_sections(&ctx, module, ELF_MODULE_RO)   ||
	   !elf_load_module_sections(&ctx, module, ELF_MODULE_DATA))
	{
		return errno = ENOMEM, NULL;
	}

	module->layout.base = module->layout.start_text;

	for(size_t i = 0; i < header->e_shnum; i++)
	{
		Elf64_Shdr *section = &sections[i];
		if(section->sh_type == SHT_RELA)
		{
			Elf64_Rela *r = (Elf64_Rela*)((char*) file + section->sh_offset);
			const size_t nr_relocs = section->sh_size / section->sh_entsize;
			for(size_t j = 0; j < nr_relocs; j++)
			{
				Elf64_Rela *rela = &r[j];
				if(elf_relocate_addend(&ctx, rela, section) == 1)
				{
					printk("Couldn't relocate the kernel module!\n");
					return errno = EINVAL, NULL;
				}
			}
		}
	}

	elf_restore_module_perms(module);

	if(!elf_setup_symtable(&ctx, module))
		return NULL;

	char *symbols_to_lookup[2] = {"module_init", "module_fini"};
	unsigned long sym_values[2] = {0, 0};

	for(size_t i = 0; i < 2; i++)
	{
		char *name = symbols_to_lookup[i];
		struct module_resolve_ctx res = {};
		res.sym_name = name;
		
		module_try_resolve(module, &res);
		
		if(!res.success)
			return errno = EINVAL, NULL;

		sym_values[i] = res.retval;
	}

	module->fini = (module_fini_t) ((void *) sym_values[1]);

	return (void *) sym_values[0];
}

bool elf_is_valid_exec(uint8_t *file)
{
	return elf_is_valid((Elf64_Ehdr*) file);
}

struct binfmt elf_binfmt = {
	.signature = (unsigned char *)"\x7f""ELF",
	.size_signature = 4,
	.callback = elf_load,
	.is_valid_exec = elf_is_valid_exec,
	.next = NULL
};

__init void __elf_init()
{
	install_binfmt(&elf_binfmt);
}
