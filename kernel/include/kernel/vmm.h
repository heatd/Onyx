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
#ifndef _VMM_H
#define _VMM_H
#include <stdint.h>
#include <kernel/pmm.h>
#include <stdbool.h>
#include <kernel/compiler.h>
/* Page table defines just to help the code not have "magic values"*/
#define _PTE_PRESENT		1
#define _PTE_WRITABLE		2
#define _PTE_USER			4
#define _PTE_WRITE_THROUGH	8
#define _PTE_NOT_CACHEABLE  0x10
#define _PTE_ACCESSED		0x20
#define _PTE_DIRTY			0x40
#define _PTE_PAT			0x80
#define _PTE_LV4_GLOBAL		0x200
#define _PTE_FRAME			0x7FFFF000
/*Page Directory defines to help the code not have "magic values"*/
#define _PDE_PRESENT		1
#define _PDE_WRITABLE		2
#define _PDE_USER			4
#define _PDE_PWT			8
#define _PDE_PCD			0x10
#define _PDE_ACCESSED		0x20
#define _PDE_DIRTY			0x40
#define _PDE_4MB			0x80
#define _PDE_CPU_GLOBAL		0x100
#define _PDE_LV4_GLOBAL		0x200
#define _PDE_FRAME			0x7FFFF000
#ifdef __i386__
typedef uint32_t pd_entry;
typedef uint32_t pt_entry;
/* i686 architecture defines 1024 entries per table */
#define PAGES_PER_TABLE 1024
#define PAGES_PER_DIR	1024
#define PAGE_DIRECTORY_INDEX(x) (((x) >> 22) & 0x3ff)
#define PAGE_TABLE_INDEX(x) (((x) >> 12) & 0x3ff)
#endif
/* page table represents 4mb address space */
#define PTABLE_ADDR_SPACE_SIZE 0x400000

/* directory table represents 4gb address space */
#define DTABLE_ADDR_SPACE_SIZE 0xFFFFFFFF

/* page sizes are 4k */
#define PAGE_SIZE 4096

/* page table */
typedef struct ptable {

	pt_entry entries[PAGES_PER_TABLE];
}ptable;

/* page directory */

typedef struct pdirectory {

	pd_entry entries[PAGES_PER_DIR];
}pdirectory;
#define PAGE_RAM 0x1
#define PAGE_KERNEL 0x2
#define PAGE_USER 0x4
#define PAGE_READ 0x1
#define PAGE_WRITE 0x2
#define PAGE_EXECUTABLE 0x4
#define PAGE_RW PAGE_READ | PAGE_WRITE
#define PAGE_RWE PAGE_RW | PAGE_EXECUTABLE
#define kernel_lowest_addr 0xC0000000
#define user_lowest_addr  0
#define MAP_KERNEL PAGE_KERNEL
#define MAP_USER   PAGE_USER
#define MAP_READ   PAGE_READ
#define MAP_WRITE  PAGE_WRITE
typedef struct area_strct
{
	uintptr_t addr; /* Address of pages */
	size_t size; /* Size in pages */
	uint8_t type; /* Type of page ( its type is uint8_t just to save some memory) */
	uint8_t protection; /* R/W, just read, executable, etc... */
	_Bool is_used; /* Is it used or not (maybe merge with the type field)*/
	struct area_strct* next; /* The next area_struct in the linked list */
}area_struct;
/*************************************************
* Arch dependent functions
* They communicate with the architecture directly, being the abstraction layer
**************************************************/
NATIVE void *_kmmap(uint32_t virt, uint32_t npages,uint32_t flags); /* Native level part of kmmap */
NATIVE void _kmunmap(void *addr, size_t size);
NATIVE int vmm_mark_addr_as_used(void*,size_t);
NATIVE void  vmm_finish();
NATIVE void *vmm_alloc_addr(size_t, _Bool);
NATIVE void  vmm_free_addr(void *address);
NATIVE int vmm_alloc_cow(uintptr_t);
NATIVE void *get_phys_addr (pdirectory *dir, uint32_t virt);
NATIVE pdirectory *get_directory();
NATIVE int _switch_directory (pdirectory* dir);
NATIVE pdirectory* _vmm_fork();
NATIVE void vmm_init(uintptr_t);
/*************************************************
* Arch neutral functions
* They communicate with the native level functions
**************************************************/
/* Function: kmmap()
*  Purpose: Map some memory into a certain address
*/
void* kmmap(uint32_t virt, uint32_t npages,uint32_t flags);
/* Function: kmunmap()
*  Purpose: Unmap some memory in a certain address
*/
void kmunmap(void* virt, size_t npages);
/* Function: valloc()
*  Purpose: Allocate a virtual address and kmmap()'it
*/
void* valloc(size_t npages, _Bool is_kernel);
/* Function: vfree()
*  Purpose: Free a virtual address and kmunmap()'it
*/
void vfree(void* ptr, uint32_t npages);
/* Function: switch_directory()
*  Purpose: Switch the paging directory
*/
int switch_directory (pdirectory* dir);
/* Function: vmm_fork()
*  Purpose: Fork the current address space
*/
pdirectory* vmm_fork();
#endif
