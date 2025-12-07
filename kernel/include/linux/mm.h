#ifndef _LINUX_MM_H
#define _LINUX_MM_H

#include <onyx/page.h>
#include <onyx/vm.h>
#include <onyx/filemap.h>
#include <onyx/mm/page_lru.h>

#include <asm/processor.h>
#include <linux/static_key.h>
#include <linux/resource.h>
#include <linux/mm_types.h>
#include <linux/sizes.h>

#define page_address(page) (PAGE_TO_VIRT((struct page *) page))
#define virt_to_phys(virt) (((unsigned long) (virt)) - PHYS_BASE)
#define virt_to_page(virt) (phys_to_page(virt_to_phys(virt)))
#define offset_in_page(addr) (((unsigned long) (addr)) & (PAGE_SIZE - 1))

#define PAGE_ALIGN(len) (((unsigned long) (len) + PAGE_SIZE - 1) & -PAGE_SIZE)

#define VM_NORESERVE (0)
#define VM_IO (0)

static inline struct page *folio_page(struct folio *folio, unsigned int index)
{
    return folio_to_page(folio) + index;
}

static inline struct page *folio_file_page(struct folio *folio, pgoff_t index)
{
    return folio_page(folio, index & (folio_nr_pages(folio) - 1));
}

#define folio_pfn(folio) (page_to_pfn(folio_to_page(folio)))
#define folio_mark_accessed(folio) (folio_promote_referenced(folio))

struct folio_batch;

void check_move_unevictable_folios(struct folio_batch *batch);

#define vm_operations_struct vm_operations

typedef unsigned long vm_flags_t;

static inline void vm_flags_set(struct vm_area_struct *vma, vm_flags_t flags)
{
    vma->vm_flags |= flags;
}

/* Don't define vm_page_prot without switching this off */
#define ONYXVM_NO_PAGE_PROT

/* TODO: fix this properly. */
#define vm_pgoff vm_offset

#endif
