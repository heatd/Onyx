/*
 * Copyright (c) 2016 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <errno.h>
#include <pthread_kernel.h>
#include <stdbool.h>
#include <stdio.h>

#include <onyx/binfmt.h>
#include <onyx/binfmt/elf64.h>
#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/elf.h>
#include <onyx/fnv.h>
#include <onyx/kernelinfo.h>
#include <onyx/log.h>
#include <onyx/modules.h>
#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/symbol.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

void *elf_load(struct binfmt_args *args);

struct elf_loader_context
{
    Elf64_Ehdr *header;
    Elf64_Shdr *sections;
    char *shstrtab;
    Elf64_Shdr *symtab;
    Elf64_Shdr *strtab;
    char *symstrtab;
    char *strings;
    Elf64_Sym *syms;
    struct file *file;
};

/* TODO: A bunch of this code requires bound-checking */

static inline char *elf_get_string(struct elf_loader_context *context, Elf64_Word off)
{
    if (context->strtab->sh_size < off)
        return nullptr;
    return context->strings + off;
}

static inline char *elf_get_shstring(struct elf_loader_context *context, Elf64_Word off)
{
    return (char *)context->shstrtab + off;
}

static Elf64_Sym *elf_get_sym(struct elf_loader_context *ctx, char *symname)
{
    Elf64_Sym *syms = ctx->syms;
    size_t nr_entries = ctx->symtab->sh_size / ctx->symtab->sh_entsize;

    for (unsigned int i = 1; i < nr_entries; i++)
    {
        char *string = elf_get_string(ctx, syms[i].st_name);
        if (!string)
            return nullptr;
        if (!strcmp(string, symname))
        {
            return &syms[i];
        }
    }

    return nullptr;
}

static inline char *elf_get_reloc_str(struct elf_loader_context *ctx, Elf64_Off off)
{
    return ctx->symstrtab + off;
}

uintptr_t get_common_block(const char *name, size_t size);

uintptr_t elf_resolve_symbol(struct elf_loader_context *ctx, size_t sym_idx)
{
    Elf64_Sym *symbol = &ctx->syms[sym_idx];

    if (symbol->st_shndx == SHN_UNDEF)
    {
        const char *name = elf_get_reloc_str(ctx, symbol->st_name);
        struct symbol *s = module_resolve_sym(name);

        if (s)
            return s->value;
        else
        {
            if (ELF64_ST_BIND(symbol->st_info) & STB_WEAK)
                return 0;
            else
            {
                return 1;
            }
        }
    }
    else if (symbol->st_shndx == SHN_ABS)
        return symbol->st_value;
    else if (symbol->st_shndx == SHN_COMMON)
    {
        const char *name = elf_get_reloc_str(ctx, symbol->st_name);
        assert(symbol->st_value <= PAGE_SIZE);
        return get_common_block(name, symbol->st_size);
    }
    else
    {
        Elf64_Shdr *tar = &ctx->sections[symbol->st_shndx];
        return (uintptr_t)ctx->header + symbol->st_value + tar->sh_offset;
    }

    return 1;
}

__attribute__((no_sanitize_undefined)) int elf_relocate_addend(struct elf_loader_context *ctx,
                                                               Elf64_Rela *rela,
                                                               Elf64_Shdr *section)
{
    Elf64_Shdr *sections = ctx->sections;
    Elf64_Shdr *target_section = &sections[section->sh_info];

    if (!(target_section->sh_flags & SHF_ALLOC))
        return 0;
    // printk("Section index: %lu\n", section->sh_info);

    /* Target section->sh_offset's were adjust as to represent the relation
     * between the load address and the ctx->header address */

    uintptr_t addr = (uintptr_t)((char *)ctx->header + target_section->sh_offset);

    // printk("Addr: %lx\n", addr);

    uintptr_t *p = (uintptr_t *)(addr + rela->r_offset);

    // printk("P: %p\n", p);

    size_t sym_idx = ELF64_R_SYM(rela->r_info);

    int32_t *ptr32s = (int32_t *)p;
    uint32_t *ptr32u = (uint32_t *)p;
    if (sym_idx != SHN_UNDEF)
    {
        uintptr_t sym = elf_resolve_symbol(ctx, sym_idx);

        switch (ELF64_R_TYPE(rela->r_info))
        {
        case R_X86_64_NONE:
            break;
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
        case R_X86_64_PLT32:
            *ptr32u = RELOCATE_R_X86_64_PC32(sym, rela->r_addend, (uintptr_t)p);
            break;
        default:
            printk("Unsuported relocation %lu!\n", ELF64_R_TYPE(rela->r_info));
            return -1;
        }
    }
    return 0;
}

bool elf_is_valid(Elf64_Ehdr *header)
{
    if (header->e_ident[EI_MAG0] != 0x7F || header->e_ident[EI_MAG1] != 'E' ||
        header->e_ident[EI_MAG2] != 'L' || header->e_ident[EI_MAG3] != 'F')
        return false;
    if (header->e_ident[EI_CLASS] != ELFCLASS64)
        return false;
    if (header->e_ident[EI_DATA] != ELFDATA2LSB)
        return false;
    if (header->e_ident[EI_VERSION] != EV_CURRENT)
        return false;
    if (header->e_ident[EI_OSABI] != ELFOSABI_SYSV)
        return false;
    if (header->e_ident[EI_ABIVERSION] != 0) /* SYSV specific */
        return false;
    return true;
}

void *elf_load(struct binfmt_args *args)
{
    bool is_interp = args->needs_interp;

    Elf64_Ehdr *header = new Elf64_Ehdr;
    if (!header)
        return errno = EINVAL, nullptr;

    if (read_vfs(0, sizeof(Elf64_Ehdr), header, args->file) < 0)
    {
        free(header);
        return nullptr;
    }

    void *entry = nullptr;
    switch (header->e_ident[EI_CLASS])
    {
    case ELFCLASS32:
        free(header);
        /* TODO: Add an elf32 loader */
        return errno = EINVAL, nullptr;
    case ELFCLASS64:
        entry = elf64_load(args, header);
        break;
    }

    free(header);

    if (args->needs_interp && !is_interp)
        entry = bin_do_interp(args);

    return entry;
}

bool elf_validate_modinfo(struct elf_loader_context *ctx)
{
    /* TODO: Maybe keep modinfo around? */

    bool modinfo_found = false;

    const size_t shnum = ctx->header->e_shnum;

    for (size_t i = 0; i < shnum; i++)
    {
        Elf64_Shdr *section = &ctx->sections[i];

        if (!strcmp(elf_get_shstring(ctx, section->sh_name), ".modinfo"))
        {
            modinfo_found = true;

            char *parse;
            char *buf = parse = (char *)malloc(section->sh_size);
            if (!parse)
                return false;

            if (read_vfs(section->sh_offset, section->sh_size, parse, ctx->file) !=
                (ssize_t)section->sh_size)
            {
                free(parse);
                return false;
            }

            char *kver = nullptr;
            for (size_t j = 0; j < section->sh_size; j++)
            {
                if (strncmp(parse, "kernel=", strlen("kernel=")) == 0)
                {
                    kver = parse + strlen("kernel=");
                    break;
                }
                parse++;
            }

            if (!kver)
            {
                free(buf);
                return false;
            }

            /* Check if the kernel version matches up */
            if (strcmp(OS_RELEASE, kver))
            {
                FATAL("module", "Kernel version does not match with the module!\n");
                free(buf);
                return false;
            }

            free(buf);
        }
    }

    return modinfo_found;
}

#define ALIGN(x, n) ((x + n - 1) & -n)

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
    for (size_t i = 0; i < ctx->header->e_shnum; i++)
    {
        Elf64_Shdr *section = &ctx->sections[i];

        if (!(section->sh_flags & SHF_ALLOC))
            continue;

        if (is_text_section(section))
        {
            layout->text_size = ALIGN(layout->text_size, section->sh_addralign);
            layout->text_size += section->sh_size;
        }
        else if (is_data_section(section))
        {
            layout->data_size = ALIGN(layout->data_size, section->sh_addralign);
            layout->data_size += section->sh_size;
        }
        else if (is_ro_section(section))
        {
            layout->ro_size = ALIGN(layout->ro_size, section->sh_addralign);
            layout->ro_size += section->sh_size;
        }
    }
#if DEBUG_MODULES
    printk("Text size: %lx\nData size: %lx\nRo size: %lx\n", layout->text_size, layout->data_size,
           layout->ro_size);
#endif
}

#define ELF_MODULE_TEXT 0
#define ELF_MODULE_RO   1
#define ELF_MODULE_DATA 2

const int module_prots[] = {0, VM_NOEXEC, VM_WRITE | VM_NOEXEC};

bool elf_load_module_sections(struct elf_loader_context *ctx, struct module *module, int type)
{
    bool (*section_checker[])(Elf64_Shdr * shdr) = {is_text_section, is_ro_section,
                                                    is_data_section};

    size_t region_size;
    /* This points to the start_* that we need to fill */
    unsigned long *addr_p = nullptr;
    if (type == ELF_MODULE_TEXT)
    {
        region_size = module->layout.text_size;
        addr_p = &module->layout.start_text;
    }
    else if (type == ELF_MODULE_RO)
    {
        region_size = module->layout.ro_size;
        addr_p = &module->layout.start_ro;
    }
    else if (type == ELF_MODULE_DATA)
    {
        region_size = module->layout.data_size;
        addr_p = &module->layout.start_data;
    }
    else
    {
        panic("bad type argument");
    }

    void *mem = module_allocate_pages(region_size, module_prots[type]);
    if (!mem)
        return false;

    *addr_p = (unsigned long)mem;

    /* Enable write, we'll fix this up in a moment */
    vm_change_perms(mem, vm_size_to_pages(region_size), VM_WRITE);

    unsigned long addr = *addr_p;
    for (size_t i = 0; i < ctx->header->e_shnum; i++)
    {
        Elf64_Shdr *section = &ctx->sections[i];
        if (section->sh_flags & SHF_ALLOC && section_checker[type](section))
        {
            addr = ALIGN(addr, section->sh_addralign);

            section->sh_addr = addr;

            if (section->sh_type == SHT_NOBITS)
            {
                /* module_allocate_pages returns zero'd memory,
                 * so don't bother to zero it out */
                /* memset(mem, 0, section->sh_size); */
            }
            else
            {
                if (read_vfs(section->sh_offset, section->sh_size, (void *)addr, ctx->file) !=
                    (ssize_t)section->sh_size)
                    return false;
            }

            section->sh_offset = (Elf64_Off)addr - (Elf64_Off)ctx->header;

            addr += section->sh_size;
        }
    }

    return true;
}

void elf_restore_module_perms(struct module *module)
{
    vm_change_perms((void *)module->layout.start_text, vm_size_to_pages(module->layout.text_size),
                    module_prots[ELF_MODULE_TEXT]);

    vm_change_perms((void *)module->layout.start_ro, vm_size_to_pages(module->layout.ro_size),
                    module_prots[ELF_MODULE_RO]);

    vm_change_perms((void *)module->layout.start_data, vm_size_to_pages(module->layout.data_size),
                    module_prots[ELF_MODULE_DATA]);
}

bool elf_setup_symtable(struct elf_loader_context *ctx, struct module *module)
{
    const size_t nr_entries = ctx->symtab->sh_size / ctx->symtab->sh_entsize;
    Elf64_Sym *symtab = ctx->syms;

    size_t nr_symbols = 0;

    for (size_t i = 0; i < nr_entries; i++)
    {
        Elf64_Sym *sym = &symtab[i];

        if (is_useful_symbol(sym))
            nr_symbols++;
    }

    struct symbol *symbol_table = (symbol *)zalloc(sizeof(struct symbol) * nr_symbols);
    if (!symbol_table)
        return false;

    for (size_t i = 0, n = 0; i < nr_entries; i++)
    {
        Elf64_Sym *sym = &symtab[i];
        Elf64_Shdr *section = &ctx->sections[sym->st_shndx];

        if (!is_useful_symbol(sym))
            continue;

        const char *name = elf_get_string(ctx, sym->st_name);
        if (!name)
            goto fail;

        struct symbol *s = &symbol_table[n];

        unsigned long base = section->sh_addr;

        sym->st_value += base;

        if (setup_symbol(s, sym, name) < 0)
            goto fail;
        n++;
    }

    module->symtable = symbol_table;
    module->nr_symtable_entries = nr_symbols;

    return true;
fail:
    for (size_t i = 0; i < nr_symbols; i++)
    {
        if (!symbol_table[i].name)
            break;
        free(symbol_table[i].name);
    }

    free(symbol_table);
    return false;
}

void *elf_load_kernel_module(struct file *file, struct module *module)
{
    void *ret = nullptr;
    struct elf_loader_context ctx = {};
    ctx.file = file;

    Elf64_Ehdr header;

    if (read_vfs(0, sizeof(Elf64_Ehdr), &header, file) != (ssize_t)sizeof(Elf64_Ehdr))
        return nullptr;

    /* Check if its elf64 file is invalid */
    if (!elf_is_valid(&header))
        return errno = EINVAL, nullptr;

    ctx.header = &header;
    Elf64_Shdr *sections = (Elf64_Shdr *)malloc(header.e_shentsize * header.e_shnum);
    if (!sections)
        return nullptr;

    if (read_vfs(header.e_shoff, header.e_shentsize * header.e_shnum, sections, file) !=
        (ssize_t)(header.e_shentsize * header.e_shnum))
    {
        free(sections);
        return nullptr;
    }

    ctx.sections = sections;
    Elf64_Shdr *shstrtab = &sections[header.e_shstrndx];

    Elf64_Shdr *symtab = nullptr, *strtab = nullptr;
    Elf64_Shdr *sec = nullptr;
    bool modinfo_valid = false;

    const char *symbols_to_lookup[2] = {"module_init", "module_fini"};
    unsigned long sym_values[2] = {0, 0};

    ctx.shstrtab = (char *)malloc(shstrtab->sh_size);
    if (!ctx.shstrtab)
    {
        goto out_error;
    }

    if (read_vfs(shstrtab->sh_offset, shstrtab->sh_size, ctx.shstrtab, file) !=
        (ssize_t)shstrtab->sh_size)
    {
        goto out_error;
    }

    for (size_t i = 0; i < header.e_shnum; i++)
    {
        if (!strcmp(elf_get_shstring(&ctx, sections[i].sh_name), ".symtab"))
            symtab = &sections[i];
        if (!strcmp(elf_get_shstring(&ctx, sections[i].sh_name), ".strtab"))
            strtab = &sections[i];
    }

    if (!symtab || !strtab)
    {
        errno = EINVAL;
        goto out_error;
    }

    ctx.strtab = strtab;
    ctx.symtab = symtab;
    ctx.strings = (char *)malloc(strtab->sh_size);
    if (!ctx.strings)
        goto out_error;

    if (read_vfs(strtab->sh_offset, strtab->sh_size, ctx.strings, file) != (ssize_t)strtab->sh_size)
        goto out_error;

    ctx.syms = (Elf64_Sym *)malloc(symtab->sh_size);
    if (!ctx.syms)
    {
        goto out_error;
    }

    /* Bad section */
    if (ctx.symtab->sh_link > header.e_shnum)
        goto out_error;

    if (read_vfs(symtab->sh_offset, symtab->sh_size, ctx.syms, file) != (ssize_t)symtab->sh_size)
    {
        goto out_error;
    }

    sec = &sections[ctx.symtab->sh_link];

    ctx.symstrtab = (char *)malloc(sec->sh_size);
    if (!ctx.symstrtab)
        goto out_error;

    if (read_vfs(sec->sh_offset, sec->sh_size, ctx.symstrtab, file) != (ssize_t)sec->sh_size)
        goto out_error;

    modinfo_valid = elf_validate_modinfo(&ctx);

    if (!modinfo_valid)
    {
        printf("elf_load_kernel_module: %s: invalid modinfo\n", module->name);
        errno = EINVAL;
        goto out_error;
    }

    elf_create_module_layout(&ctx, module);

    if (!elf_load_module_sections(&ctx, module, ELF_MODULE_TEXT) ||
        !elf_load_module_sections(&ctx, module, ELF_MODULE_RO) ||
        !elf_load_module_sections(&ctx, module, ELF_MODULE_DATA))
    {
        errno = ENOMEM;
        goto out_error;
    }

    module->layout.base = module->layout.start_text;

    for (size_t i = 0; i < header.e_shnum; i++)
    {
        Elf64_Shdr *section = &sections[i];
        if (section->sh_type == SHT_RELA)
        {
            Elf64_Rela *r = (Elf64_Rela *)malloc(section->sh_size);
            if (!r)
            {
                goto out_error;
            }

            if (read_vfs(section->sh_offset, section->sh_size, r, file) !=
                (ssize_t)section->sh_size)
            {
                free(r);
                goto out_error;
            }

            const size_t nr_relocs = section->sh_size / section->sh_entsize;
            for (size_t j = 0; j < nr_relocs; j++)
            {
                Elf64_Rela *rela = &r[j];
                if (elf_relocate_addend(&ctx, rela, section) < 0)
                {
                    printk("Couldn't relocate the kernel module!\n");
                    free(r);
                    errno = EINVAL;
                    goto out_error;
                }
            }

            free(r);
        }
    }

    elf_restore_module_perms(module);

    if (!elf_setup_symtable(&ctx, module))
        goto out_error;

    for (size_t i = 0; i < 2; i++)
    {
        const char *name = symbols_to_lookup[i];
        struct module_resolve_ctx res = {};
        res.flags = SYMBOL_RESOLVE_MAY_BE_STATIC;
        res.sym_name = name;

        module_try_resolve(module, &res);

        /* module_fini isn't required to exist */
        if (!res.success && i == 0)
            goto out_error;

        if (res.success)
            sym_values[i] = res.sym->value;
    }

    module->fini = (module_fini_t)((void *)sym_values[1]);

    ret = (void *)sym_values[0];

    /* Exit re-used between the error path and normal exit path */
out_error:
    free(ctx.shstrtab);
    free(ctx.sections);
    free(ctx.syms);
    free(ctx.symstrtab);
    free(ctx.strings);

    return ret;
}

bool elf_is_valid_exec(uint8_t *file)
{
    return elf_is_valid((Elf64_Ehdr *)file);
}

struct binfmt elf_binfmt = {.signature = (unsigned char *)"\x7f"
                                                          "ELF",
                            .size_signature = 4,
                            .is_valid_exec = elf_is_valid_exec,
                            .callback = elf_load,
                            .next = nullptr};

__init static void __elf_init()
{
    install_binfmt(&elf_binfmt);
}
