/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/elf.h>
#include <onyx/fnv.h>
#include <onyx/log.h>
#include <onyx/modules.h>
#include <onyx/panic.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/symbol.h>
#include <onyx/uname.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include <platform/elf.h>

#if __SIZE_WIDTH__ == 64

using elf_ehdr = Elf64_Ehdr;
using elf_phdr = Elf64_Phdr;
using elf_half = Elf64_Half;
using elf_dyn = Elf64_Dyn;
using elf_shdr = Elf64_Shdr;
using elf_sym = Elf64_Sym;
using elf_word = Elf64_Word;
using elf_off = Elf64_Off;
using elf_rela = Elf64_Rela;
#define ELF_BITS 64

#define ELFCLASS ELFCLASS64

#define ELF_R_SYM  ELF64_R_SYM
#define ELF_R_TYPE ELF64_R_TYPE

#endif

// ELF_ST_BIND == ELF64_ST_BIND == ELF32_ST_BIND
// the same applies for the others

#define ELF_ST_BIND(val)        ELF64_ST_BIND(val)
#define ELF_ST_TYPE(val)        ELF64_ST_TYPE(val)
#define ELF_ST_INFO(bind, type) ELF64_ST_INFO((bind), (type))

struct elf_loader_context
{
    elf_ehdr *header;
    elf_shdr *sections;
    char *shstrtab;
    elf_shdr *symtab;
    elf_shdr *strtab;
    char *symstrtab;
    char *strings;
    elf_sym *syms;
    struct file *file;
};

/* TODO: A bunch of this code requires bound-checking */

static inline char *elf_get_string(struct elf_loader_context *context, elf_word off)
{
    if (context->strtab->sh_size <= off)
        return nullptr;
    return context->strings + off;
}

static inline char *elf_get_shstring(struct elf_loader_context *context, elf_word off)
{
    return (char *) context->shstrtab + off;
}

static elf_sym *elf_get_sym(struct elf_loader_context *ctx, char *symname)
{
    elf_sym *syms = ctx->syms;
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

static inline char *elf_get_reloc_str(struct elf_loader_context *ctx, elf_off off)
{
    return ctx->symstrtab + off;
}

uintptr_t get_common_block(const char *name, size_t size);

uintptr_t elf_resolve_symbol(struct elf_loader_context *ctx, size_t sym_idx)
{
    elf_sym *symbol = &ctx->syms[sym_idx];

    if (symbol->st_shndx == SHN_UNDEF)
    {
        const char *name = elf_get_reloc_str(ctx, symbol->st_name);
        struct symbol *s = module_resolve_sym(name);

        if (s)
            return s->value;
        else
        {
            if (ELF_ST_BIND(symbol->st_info) & STB_WEAK)
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
        elf_shdr *tar = &ctx->sections[symbol->st_shndx];
        return (uintptr_t) ctx->header + symbol->st_value + tar->sh_offset;
    }

    return 1;
}

__attribute__((no_sanitize_undefined)) int elf_relocate_addend(struct elf_loader_context *ctx,
                                                               elf_rela *rela, elf_shdr *section)
{
    elf_shdr *sections = ctx->sections;
    elf_shdr *target_section = &sections[section->sh_info];

    if (!(target_section->sh_flags & SHF_ALLOC))
        return 0;

    /* Target section->sh_offset's were adjusted as to represent the relation
     * between the load address and the ctx->header address */

    uintptr_t addr = (uintptr_t) ((char *) ctx->header + target_section->sh_offset);

    size_t sym_idx = ELF_R_SYM(rela->r_info);

    if (sym_idx != SHN_UNDEF)
    {
        uintptr_t sym = elf_resolve_symbol(ctx, sym_idx);

        auto type = ELF_R_TYPE(rela->r_info);

        if (arch_elf_do_rela(addr, rela, sym, type) < 0)
        {
            printk("Unsuported relocation %lu!\n", type);
            return -1;
        }
    }

    return 0;
}

static bool elf_is_valid(elf_ehdr *header)
{
    if (header->e_ident[EI_MAG0] != ELFMAG0 || header->e_ident[EI_MAG1] != ELFMAG1 ||
        header->e_ident[EI_MAG2] != ELFMAG2 || header->e_ident[EI_MAG3] != ELFMAG3)
        return false;
    if (header->e_ident[EI_CLASS] != ELFCLASS)
        return false;
    if (header->e_ident[EI_DATA] != ELFDATA2LSB)
        return false;
    if (header->e_ident[EI_VERSION] != EV_CURRENT)
        return false;
    if (header->e_ident[EI_OSABI] != ELFOSABI_SYSV)
        return false;
    if (header->e_ident[EI_ABIVERSION] != 0) /* SYSV specific */
        return false;
    if (header->e_machine != EM_CURRENT)
        return false;

    return true;
}

bool elf_validate_modinfo(struct elf_loader_context *ctx)
{
    /* TODO: Maybe keep modinfo around? */

    bool modinfo_found = false;

    const size_t shnum = ctx->header->e_shnum;

    for (size_t i = 0; i < shnum; i++)
    {
        elf_shdr *section = &ctx->sections[i];

        if (!strcmp(elf_get_shstring(ctx, section->sh_name), ".modinfo"))
        {
            modinfo_found = true;

            char *parse;
            char *buf = parse = (char *) malloc(section->sh_size);
            if (!parse)
                return false;

            if (read_vfs(section->sh_offset, section->sh_size, parse, ctx->file) !=
                (ssize_t) section->sh_size)
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

static inline bool is_text_section(elf_shdr *section)
{
    bool is_write = section->sh_flags & SHF_WRITE;
    bool is_exec = section->sh_flags & SHF_EXECINSTR;
    return (!is_write && is_exec);
}

static inline bool is_data_section(elf_shdr *section)
{
    bool is_write = section->sh_flags & SHF_WRITE;
    bool is_exec = section->sh_flags & SHF_EXECINSTR;
    return (is_write && !is_exec);
}

static inline bool is_ro_section(elf_shdr *section)
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
        elf_shdr *section = &ctx->sections[i];

        if (!(section->sh_flags & SHF_ALLOC))
            continue;

        if (is_text_section(section))
        {
            layout->text_size = ALIGN_TO(layout->text_size, section->sh_addralign);
            layout->text_size += section->sh_size;
        }
        else if (is_data_section(section))
        {
            layout->data_size = ALIGN_TO(layout->data_size, section->sh_addralign);
            layout->data_size += section->sh_size;
        }
        else if (is_ro_section(section))
        {
            layout->ro_size = ALIGN_TO(layout->ro_size, section->sh_addralign);
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

const int module_prots[] = {VM_EXEC, VM_READ, VM_READ | VM_WRITE};

bool elf_load_module_sections(struct elf_loader_context *ctx, struct module *module, int type)
{
    bool (*section_checker[])(elf_shdr * shdr) = {is_text_section, is_ro_section, is_data_section};

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

    *addr_p = (unsigned long) mem;

    /* Enable write, we'll fix this up in a moment */
    vm_do_mmu_mprotect(&kernel_address_space, mem, vm_size_to_pages(region_size),
                       VM_READ | VM_WRITE, VM_READ | VM_WRITE);

    unsigned long addr = *addr_p;
    for (size_t i = 0; i < ctx->header->e_shnum; i++)
    {
        elf_shdr *section = &ctx->sections[i];
        if (section->sh_flags & SHF_ALLOC && section_checker[type](section))
        {
            addr = ALIGN_TO(addr, section->sh_addralign);

            section->sh_addr = addr;

            if (section->sh_type == SHT_NOBITS)
            {
                /* module_allocate_pages returns zero'd memory,
                 * so don't bother to zero it out */
                /* memset(mem, 0, section->sh_size); */
            }
            else
            {
                if (read_vfs(section->sh_offset, section->sh_size, (void *) addr, ctx->file) !=
                    (ssize_t) section->sh_size)
                    return false;
            }

            section->sh_offset = (elf_off) addr - (elf_off) ctx->header;

            addr += section->sh_size;
        }
    }

    return true;
}

void elf_restore_module_perms(struct module *module)
{
    vm_do_mmu_mprotect(&kernel_address_space, (void *) module->layout.start_text,
                       vm_size_to_pages(module->layout.text_size), VM_READ | VM_WRITE,
                       module_prots[ELF_MODULE_TEXT]);

    vm_do_mmu_mprotect(&kernel_address_space, (void *) module->layout.start_ro,
                       vm_size_to_pages(module->layout.ro_size), VM_READ | VM_WRITE,
                       module_prots[ELF_MODULE_RO]);

    vm_do_mmu_mprotect(&kernel_address_space, (void *) module->layout.start_data,
                       vm_size_to_pages(module->layout.data_size), VM_READ | VM_WRITE,
                       module_prots[ELF_MODULE_DATA]);
}

bool elf_setup_symtable(struct elf_loader_context *ctx, struct module *module)
{
    const size_t nr_entries = ctx->symtab->sh_size / ctx->symtab->sh_entsize;
    elf_sym *symtab = ctx->syms;

    size_t nr_symbols = 0;

    for (size_t i = 0; i < nr_entries; i++)
    {
        elf_sym *sym = &symtab[i];

        if (is_useful_symbol(sym))
            nr_symbols++;
    }

    struct symbol *symbol_table = (symbol *) zalloc(sizeof(struct symbol) * nr_symbols);
    if (!symbol_table)
        return false;

    for (size_t i = 0, n = 0; i < nr_entries; i++)
    {
        elf_sym *sym = &symtab[i];
        elf_shdr *section = &ctx->sections[sym->st_shndx];

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

    elf_ehdr header;

    if (read_vfs(0, sizeof(elf_ehdr), &header, file) != (ssize_t) sizeof(elf_ehdr))
        return nullptr;

    /* Check if its elf file is invalid */
    if (!elf_is_valid(&header))
        return errno = EINVAL, nullptr;

    ctx.header = &header;
    elf_shdr *sections = (elf_shdr *) malloc(header.e_shentsize * header.e_shnum);
    if (!sections)
        return nullptr;

    if (read_vfs(header.e_shoff, header.e_shentsize * header.e_shnum, sections, file) !=
        (ssize_t) (header.e_shentsize * header.e_shnum))
    {
        free(sections);
        return nullptr;
    }

    ctx.sections = sections;
    elf_shdr *shstrtab = &sections[header.e_shstrndx];

    elf_shdr *symtab = nullptr, *strtab = nullptr;
    elf_shdr *sec = nullptr;
    bool modinfo_valid = false;

    const char *symbols_to_lookup[2] = {"module_init", "module_fini"};
    unsigned long sym_values[2] = {0, 0};

    ctx.shstrtab = (char *) malloc(shstrtab->sh_size);
    if (!ctx.shstrtab)
    {
        goto out_error;
    }

    if (read_vfs(shstrtab->sh_offset, shstrtab->sh_size, ctx.shstrtab, file) !=
        (ssize_t) shstrtab->sh_size)
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
    ctx.strings = (char *) malloc(strtab->sh_size);
    if (!ctx.strings)
        goto out_error;

    if (read_vfs(strtab->sh_offset, strtab->sh_size, ctx.strings, file) !=
        (ssize_t) strtab->sh_size)
        goto out_error;

    ctx.syms = (elf_sym *) malloc(symtab->sh_size);
    if (!ctx.syms)
    {
        goto out_error;
    }

    /* Bad section */
    if (ctx.symtab->sh_link > header.e_shnum)
        goto out_error;

    if (read_vfs(symtab->sh_offset, symtab->sh_size, ctx.syms, file) != (ssize_t) symtab->sh_size)
    {
        goto out_error;
    }

    sec = &sections[ctx.symtab->sh_link];

    ctx.symstrtab = (char *) malloc(sec->sh_size);
    if (!ctx.symstrtab)
        goto out_error;

    if (read_vfs(sec->sh_offset, sec->sh_size, ctx.symstrtab, file) != (ssize_t) sec->sh_size)
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
        elf_shdr *section = &sections[i];
        if (section->sh_type == SHT_RELA)
        {
            elf_rela *r = (elf_rela *) malloc(section->sh_size);
            if (!r)
            {
                goto out_error;
            }

            if (read_vfs(section->sh_offset, section->sh_size, r, file) !=
                (ssize_t) section->sh_size)
            {
                free(r);
                goto out_error;
            }

            const size_t nr_relocs = section->sh_size / section->sh_entsize;
            for (size_t j = 0; j < nr_relocs; j++)
            {
                elf_rela *rela = &r[j];
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

    module->fini = (module_fini_t) ((void *) sym_values[1]);

    ret = (void *) sym_values[0];

    /* Exit re-used between the error path and normal exit path */
out_error:
    free(ctx.shstrtab);
    free(ctx.sections);
    free(ctx.syms);
    free(ctx.symstrtab);
    free(ctx.strings);

    return ret;
}
