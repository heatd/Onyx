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
#ifndef _ELF_LOADER_H
#define _ELF_LOADER_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

// Standard elf64 types
typedef uint64_t Elf64_Addr;
typedef uint64_t Elf64_Off;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf64_Word;
typedef int32_t  Elf64_Sword;
typedef uint64_t Elf64_Xword;
typedef int64_t  Elf64_Sxword;

// e_ident values
#define EI_MAG0 (0)
#define EI_MAG1 (1)
#define EI_MAG2 (2)
#define EI_MAG3 (3)
#define EI_CLASS (4)
#define EI_DATA (5)
#define EI_VERSION (6)
#define EI_OSABI (7)
#define EI_ABIVERSION (8)
#define EI_PAD (9)
#define EI_NIDENT (16)

typedef struct
{
	unsigned char e_ident[EI_NIDENT];
    	Elf64_Half e_type;
    	Elf64_Half e_machine;
    	Elf64_Word e_version;
    	Elf64_Addr e_entry;
    	Elf64_Off e_phoff;
    	Elf64_Off e_shoff;
    	Elf64_Word e_flags;
    	Elf64_Half e_ehsize;
    	Elf64_Half e_phentsize;
    	Elf64_Half e_phnum;
    	Elf64_Half e_shentsize;
    	Elf64_Half e_shnum;
    	Elf64_Half e_shstrndx;
} Elf64_Ehdr;
typedef struct
{
    	Elf64_Word p_type;
    	Elf64_Word p_flags;
    	Elf64_Off p_offset;
    	Elf64_Addr p_vaddr;
    	Elf64_Addr p_paddr;
    	Elf64_Xword p_filesz;
    	Elf64_Xword p_memsz;
    	Elf64_Xword p_align;
} Elf64_Phdr;

#define ELF_MAGIC "\x7F""ELF"
// EI_CLASS values
#define ELFCLASS32 (1)
#define ELFCLASS64 (2)

#define ELFDATA2LSB (1)
#define ELFDATA2MSB (2)
// OS ABI's
#define ELFOSABI_SYSV (0)
#define ELFOSABI_STANDALONE (255)
// Object file types
#define ET_NONE (0)
#define ET_REL (1) // Relocatable file
#define ET_EXEC (2) // Executable file
#define ET_DYN (3) // Shared library
#define ET_CORE (4) // Core file

#define EV_CURRENT (1)

#define PT_NULL (0)
#define PT_LOAD (1)
_Bool elf_is_valid(Elf64_Ehdr* header);
void* elf_load(void* file);
#endif
