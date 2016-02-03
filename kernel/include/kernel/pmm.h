
#ifndef PMM_H
#define PMM_H


#include <stdint.h>
#include <stddef.h>
typedef uint32_t physical_addr;
#define PMMNGR_BLOCKS_PER_BYTE 8

//! block size (4k)
#define PMMNGR_BLOCK_SIZE	4096

//! block alignment
#define PMMNGR_BLOCK_ALIGN	PMMNGR_BLOCK_SIZE
void*	pmmngr_alloc_block ();
void	pmmngr_init_region (physical_addr base, size_t size);
void	pmmngr_deinit_region (physical_addr base, size_t size);
void	pmmngr_init (size_t memSize, physical_addr bitmap);
void	pmmngr_free_block (void* p);


#endif // PMM_H
