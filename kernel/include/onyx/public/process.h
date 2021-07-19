/*
* Copyright (c) 2021 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_PUBLIC_PROCESS_H
#define _ONYX_PUBLIC_PROCESS_H

#include <stdint.h>
#include <stddef.h>
#include <limits.h>

enum process_query
{
	PROCESS_GET_PATH = 0,
	PROCESS_GET_NAME,
    PROCESS_GET_MM_INFO,
    PROCESS_GET_VM_REGIONS
};

struct onx_process_mm_info
{
    // The start of the address space
    uint64_t start;
    // The end of the address space
    uint64_t end;

    // mmap region base 
    uint64_t mmap_base;
    // Current brk pointer
    uint64_t brk;

    // Stats, most can be seen in getrusage too
    uint64_t virtual_memory_size;
	uint64_t resident_set_size;
	uint64_t shared_set_size;
	uint64_t page_faults;
	uint64_t page_tables_size;
};

struct onx_process_vm_region
{
    uint64_t start;
    uint64_t length;

    uint32_t protection;
    uint32_t mapping_type;
    uint64_t offset;

    char name[NAME_MAX + 1];
    // sha256 hash of the pointer
    unsigned char vmo_identifier[32];
};

#define VM_REGION_PROT_READ 			(1 << 0)
#define VM_REGION_PROT_WRITE 			(1 << 1)
#define VM_REGION_PROT_EXEC 			(1 << 2)
#define VM_REGION_PROT_NOCACHE			(1 << 3)
#define VM_REGION_PROT_WRITETHROUGH		(1 << 4)
#define VM_REGION_PROT_WC				(1 << 5)
#define VM_REGION_PROT_WP				(1 << 6)

#endif
