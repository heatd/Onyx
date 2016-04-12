/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#ifndef _ELF_LOADER_H
#define _ELF_LOADER_H
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
typedef uint16_t Elf32_Half;	/* Unsigned half int */
typedef uint32_t Elf32_Off;	/* Unsigned offset */
typedef uint32_t Elf32_Addr;	/* Unsigned address */
typedef uint32_t Elf32_Word;	/* Unsigned int */
typedef int32_t  Elf32_Sword;	/* Signed int */

#define ELF_NIDENT	16
typedef struct {
        Elf32_Word      p_type;
        Elf32_Off       p_offset;
        Elf32_Addr      p_vaddr;
        Elf32_Addr      p_paddr;
        Elf32_Word      p_filesz;
        Elf32_Word      p_memsz;
        Elf32_Word      p_flags;
        Elf32_Word      p_align;
} Elf32_Phdr;
typedef struct {
	uint8_t		e_ident[ELF_NIDENT];
	Elf32_Half	e_type;
	Elf32_Half	e_machine;
	Elf32_Word	e_version;
	Elf32_Addr	e_entry;
	Elf32_Off	e_phoff;
	Elf32_Off	e_shoff;
	Elf32_Word	e_flags;
	Elf32_Half	e_ehsize;
	Elf32_Half	e_phentsize;
	Elf32_Half	e_phnum;
	Elf32_Half	e_shentsize;
	Elf32_Half	e_shnum;
	Elf32_Half	e_shstrndx;
} Elf32_Ehdr;
typedef struct {
	Elf32_Word	sh_name;
	Elf32_Word	sh_type;
	Elf32_Word	sh_flags;
	Elf32_Addr	sh_addr;
	Elf32_Off	sh_offset;
	Elf32_Word	sh_size;
	Elf32_Word	sh_link;
	Elf32_Word	sh_info;
	Elf32_Word	sh_addralign;
	Elf32_Word	sh_entsize;
} Elf32_Shdr;
enum Elf_Ident {
	EI_MAG0		= 0, /* 0x7F */
	EI_MAG1		= 1, /* 'E' */
	EI_MAG2		= 2, /* 'L' */
	EI_MAG3		= 3, /* 'F' */
	EI_CLASS	= 4, /* Architecture (32/64) */
	EI_DATA		= 5, /* Byte Order */
	EI_VERSION	= 6, /* ELF Version */
	EI_OSABI	= 7, /* OS Specific */
	EI_ABIVERSION	= 8, /* OS Specific */
	EI_PAD		= 9  /* Padding */
};
#define SHN_UNDEF	(0x00) // Undefined/Not present
#define SHN_LORESERVE 0xFF00
#define SHN_LOPROC 0xFF00
#define SHN_HIPROC 0xFF1F
#define SHN_ABS 0xfff1
#define SHN_COMMON 0xfff2
#define SHN_HIRESERVE 0xffff
enum ShT_Types {
	SHT_NULL	= 0,   // Null section
	SHT_PROGBITS	= 1,   // Program information
	SHT_SYMTAB	= 2,   // Symbol table
	SHT_STRTAB	= 3,   // String table
	SHT_RELA	= 4,   // Relocation (w/ addend)
	SHT_NOBITS	= 8,   // Not present in file
	SHT_REL		= 9,   // Relocation (no addend)
};

enum ShT_Attributes {
	SHF_WRITE	= 0x01, // Writable section
	SHF_ALLOC	= 0x02  // Exists in memory
};
#define ELFMAG0	0x7F /* e_ident[EI_MAG0] */
#define ELFMAG1	'E'  /* e_ident[EI_MAG1] */
#define ELFMAG2	'L'  /* e_ident[EI_MAG2] */
#define ELFMAG3	'F'  /* e_ident[EI_MAG3] */

#define ELFDATA2LSB	(1)  /* Little Endian */
#define ELFCLASS32	(1)  /* 32-bit Architecture */

enum Elf_Type {
	ET_NONE		= 0, /* Unknown Type */
	ET_REL		= 1, /* Relocatable File */
	ET_EXEC		= 2  /* Executable File */
};

#define EM_386		(3)  /* x86 Machine Type */
#define EV_CURRENT	(1)  /* ELF Current Version */
#define HDR_INV 	0x1
#define ARCH_INV 	0x2
#define DATAORDER_INV 	0x3
typedef struct {
	Elf32_Word		st_name;
	Elf32_Addr		st_value;
	Elf32_Word		st_size;
	uint8_t			st_info;
	uint8_t			st_other;
	Elf32_Half		st_shndx;
} Elf32_Sym;

# define ELF32_ST_BIND(INFO)	((INFO) >> 4)
# define ELF32_ST_TYPE(INFO)	((INFO) & 0x0F)

enum StT_Bindings {
	STB_LOCAL		= 0, // Local scope
	STB_GLOBAL		= 1, // Global scope
	STB_WEAK		= 2  // Weak, (ie. __attribute__((weak)))
};

enum StT_Types {
	STT_NOTYPE		= 0, // No type
	STT_OBJECT		= 1, // Variables, arrays, etc.
	STT_FUNC		= 2  // Methods or functions
};
typedef struct {
	Elf32_Addr		r_offset;
	Elf32_Word		r_info;
} Elf32_Rel;

typedef struct {
	Elf32_Addr		r_offset;
	Elf32_Word		r_info;
	Elf32_Sword		r_addend;
} Elf32_Rela;

# define ELF32_R_SYM(INFO)	((INFO) >> 8)
# define ELF32_R_TYPE(INFO)	((uint8_t)(INFO))

enum RtT_Types {
	R_386_NONE		= 0, // No relocation
	R_386_32		= 1, // Symbol + Offset
	R_386_PC32		= 2  // Symbol + Offset - Section Offset
};
# define ELF_RELOC_ERR -1
/* Function Declarations */
_Bool elf_load_file(char *file);
_Bool elf_check_supported(Elf32_Ehdr *header);
int elf_parse_program_heade(Elf32_Phdr *prog_hdr,Elf32_Half entries,char *file);
void throw_error(int errn,const char* err_msg);
#endif
