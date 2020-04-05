#include <elf.h>
#include <link.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "libc.h"
#include "syscall.h"

#ifdef VDSO_USEFUL

#if ULONG_MAX == 0xffffffff
typedef Elf32_Ehdr Ehdr;
typedef Elf32_Phdr Phdr;
typedef Elf32_Shdr Shdr;
typedef Elf32_Sym Sym;
typedef Elf32_Verdef Verdef;
typedef Elf32_Verdaux Verdaux;
#else
typedef Elf64_Ehdr Ehdr;
typedef Elf64_Phdr Phdr;
typedef Elf64_Shdr Shdr;
typedef Elf64_Sym Sym;
typedef Elf64_Verdef Verdef;
typedef Elf64_Verdaux Verdaux;
#endif

#define OK_TYPES (1<<STT_NOTYPE | 1<<STT_OBJECT | 1<<STT_FUNC | 1<<STT_COMMON)
#define OK_BINDS (1<<STB_GLOBAL | 1<<STB_WEAK | 1<<STB_GNU_UNIQUE)

static bool vdso_present = false;
static Sym *syms = NULL;
static char *strings = NULL;
static Elf_Symndx *hashtab = NULL;
static size_t base = -1;
static Shdr *sections = NULL;

void __vdso_init(void)
{
	size_t i;
	for(i = 0; libc.auxv[i] != AT_SYSINFO_EHDR; i += 2)
		if (!libc.auxv[i]) return;
	if(!libc.auxv[i + 1]) return;
	Ehdr *eh = (void *) libc.auxv[i + 1];
	Phdr *ph = (void *)((char *) eh + eh->e_phoff);
	sections = (void *)((char *) eh + eh->e_shoff);
	base = (size_t) eh;

	size_t *dynv = 0;
	for (i = 0; i < eh->e_phnum; i++, ph = (void *)((char *) ph + eh->e_phentsize)) {
		if(ph->p_type == PT_DYNAMIC)
			dynv = (void *)((char *) eh + ph->p_offset);
	}
	if(!dynv || base == (size_t) -1) return;
	
	for( i = 0; dynv[i]; i += 2) {
		void *p = (void *)(base + dynv[i + 1]);
		switch(dynv[i]) {
		case DT_STRTAB: strings = p; break;
		case DT_SYMTAB: syms = p; break;
		case DT_HASH: hashtab = p; break;
		}
	}	

	if (!strings || !syms || !hashtab) return;

	vdso_present = true;
}

void *__vdsosym(const char *vername, const char *name)
{
	if(!vdso_present)
		return NULL;

	for(size_t i = 0; i < hashtab[1]; i++) {
		if(!(1 << (syms[i].st_info & 0xf) & OK_TYPES)) continue;
		if(!(1 << (syms[i].st_info >> 4) & OK_BINDS)) continue;
		if(!syms[i].st_shndx) continue;
		if(strcmp(name, strings + syms[i].st_name)) continue;
		return (void *)(base + syms[i].st_value);
	}

	return NULL;
}

#endif
