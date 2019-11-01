/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <mbr.h>
#include <multiboot2.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <pthread_kernel.h>
#include <partitions.h>
#include <assert.h>

#include <sys/mman.h>
#include <acpica/acpi.h>

#include <onyx/debug.h>
#include <onyx/slab.h>
#include <onyx/vm.h>
#include <onyx/paging.h>
#include <onyx/idt.h>
#include <onyx/tty.h>
#include <onyx/panic.h>
#include <onyx/cpu.h>
#include <onyx/pit.h>
#include <onyx/vfs.h>
#include <onyx/initrd.h>
#include <onyx/task_switching.h>
#include <onyx/binfmt.h>
#include <onyx/elf.h>
#include <onyx/tss.h>
#include <onyx/heap.h>
#include <onyx/acpi.h>
#include <onyx/power_management.h>
#include <onyx/udp.h>
#include <onyx/dhcp.h>
#include <onyx/modules.h>
#include <onyx/ethernet.h>
#include <onyx/random.h>
#include <onyx/dev.h>
#include <onyx/bootmem.h>
#include <onyx/log.h>
#include <onyx/dns.h>
#include <onyx/icmp.h>
#include <onyx/process.h>
#include <onyx/block.h>
#include <onyx/elf.h>
#include <onyx/smbios.h>
#include <onyx/fscache.h>
#include <onyx/page.h>
#include <onyx/irq.h>
#include <onyx/vdso.h>
#include <onyx/timer.h>
#include <onyx/worker.h>
#include <onyx/utils.h>
#include <onyx/sysfs.h>
#include <onyx/pagecache.h>
#include <onyx/driver.h>
#include <onyx/rwlock.h>
#include <onyx/crypt/sha256.h>
#include <onyx/clock.h>
#include <onyx/percpu.h>
#include <onyx/framebuffer.h>
#include <onyx/utils.h>
#include <onyx/mm/kasan.h>

#include <drivers/rtc.h>

static struct multiboot_tag_module *initrd_tag = NULL;
struct multiboot_tag_elf_sections *secs;
struct multiboot_tag_mmap *mmap_tag = NULL;
ACPI_TABLE_RSDP grub2_rsdp = {0};

uintptr_t get_rdsp_from_grub(void)
{
	return ((uintptr_t) &grub2_rsdp) - KERNEL_VIRTUAL_BASE;
}

extern uintptr_t kernel_end;
char *get_kernel_cmdline(void);
void set_initrd_address(void *initrd_address);

static struct framebuffer fb = 
{
	.name = "multiboot2-fb"
};

#define CALCULATE_MASK(shift, size)	(((1 << size) - 1) << shift)
void init_multiboot2_framebuffer(struct multiboot_tag_framebuffer *tagfb)
{
	fb.framebuffer_phys = tagfb->common.framebuffer_addr;
	fb.height = tagfb->common.framebuffer_height;
	fb.width = tagfb->common.framebuffer_width;
	fb.bpp = tagfb->common.framebuffer_bpp;
	fb.pitch = tagfb->common.framebuffer_pitch;

	size_t framebuffer_size = fb.width * fb.height * (fb.bpp/CHAR_BIT);
	fb.framebuffer_size = framebuffer_size;

	fb.framebuffer = mmiomap((void *) fb.framebuffer_phys,
		framebuffer_size, VM_WRITE | VM_NOEXEC | VM_WC);
	
	if(!fb.framebuffer)
	{
		/* Err, I guess that we have no fb, so just ret */
		return;
	}

	fb.color.blue_shift = tagfb->framebuffer_blue_field_position;
	fb.color.green_shift = tagfb->framebuffer_green_field_position;
	fb.color.red_shift = tagfb->framebuffer_red_field_position;

	fb.color.blue_mask = CALCULATE_MASK(fb.color.blue_shift,
		tagfb->framebuffer_blue_mask_size);
	fb.color.green_mask = CALCULATE_MASK(fb.color.green_shift,
		tagfb->framebuffer_green_mask_size);
	fb.color.red_mask = CALCULATE_MASK(fb.color.red_shift,
		tagfb->framebuffer_red_mask_size);

	set_framebuffer(&fb);

}

#define BITMAP_SIZE (0x1000000 / PAGE_SIZE / sizeof(unsigned long) / CHAR_BIT)
#define PAGES_PER_ENTRY (sizeof(unsigned long) * CHAR_BIT)

unsigned long dma_mem_bitmap[BITMAP_SIZE];

/* TODO: This doesn't work bcs it doesn't take into account the number of pages */
void *multiboot2_alloc_boot_page_low(size_t nr_pages)
{
	for(size_t i = 0; i < BITMAP_SIZE; ++i)
	{
		if(dma_mem_bitmap[i] == 0xffffffffffffffff)
			continue;
		for(size_t j = 0; j < PAGES_PER_ENTRY; j++)
		{
			if(!(dma_mem_bitmap[i] & (1UL << j)))
			{
				dma_mem_bitmap[i] |= (1UL << j);
				return (void *) (i * PAGES_PER_ENTRY * PAGE_SIZE + j * PAGE_SIZE);
			}
		}
	}

	return NULL;
}

bool page_is_used(void *__page, struct bootmodule *modules);

struct bootmodule initrd;

bool range_is_used(unsigned long addr, size_t nr_pages)
{
	unsigned long l = addr;
	for(size_t j = 0; j < nr_pages; j++)
	{
		if(page_is_used((void *) (l), &initrd))
		{
			return true;
		}

		l += PAGE_SIZE;
	}

	return false;
}

void *multiboot2_alloc_boot_page_high(size_t nr_pages)
{
	size_t entries = mmap_tag->size / mmap_tag->entry_size;
	struct multiboot_mmap_entry *mmap = (struct multiboot_mmap_entry *) mmap_tag->entries + entries-1;
	size_t i = 0;

	for(; i < entries; i++, mmap--)
	{
		if(mmap->type != MULTIBOOT_MEMORY_AVAILABLE)
			continue;
	
		if(mmap->len >> PAGE_SHIFT >= nr_pages)
		{
			if(!range_is_used(mmap->addr, nr_pages))
			{
				uintptr_t ret = mmap->addr;
				mmap->addr += nr_pages << PAGE_SHIFT;
				mmap->len -= nr_pages << PAGE_SHIFT;
				return (void *) ret;
			}
			else if(!range_is_used(mmap->addr + mmap->len -
				(nr_pages << PAGE_SHIFT), nr_pages))
			{
				unsigned long ret = mmap->addr + mmap->len - (nr_pages << PAGE_SHIFT);
				mmap->len -= nr_pages << PAGE_SHIFT;
				return (void *) ret;
			}

		}
	}

	return NULL;
}

void *multiboot2_alloc_boot_page(size_t nr_pages, long flags)
{
	if(flags & BOOTMEM_FLAG_LOW_MEM)
		return multiboot2_alloc_boot_page_low(nr_pages);
	else
		return multiboot2_alloc_boot_page_high(nr_pages);
}

void *multiboot2_get_phys_mem_region(uintptr_t *base,
	uintptr_t *size, void *context)
{
	/* Context holds an array index */

	struct multiboot_tag_mmap *tag = mmap_tag;
	size_t entries = mmap_tag->size / mmap_tag->entry_size;
	size_t curr_entry = (size_t) context;

	if(curr_entry == entries)
		return (void *) 0;

	struct multiboot_mmap_entry *entry = &tag->entries[curr_entry];

	printf("Adding physical memory region %llx - %llx\n", entry->addr, entry->addr + entry->len);
	*base = entry->addr;
	*size = entry->len;

	curr_entry++;

	for(; curr_entry != entries; ++curr_entry)
	{
		if(tag->entries[curr_entry].type == MULTIBOOT_MEMORY_AVAILABLE)
			break;
	}

	return (void *) curr_entry;
	
}

void low_mem_allocator_clear(uintptr_t page)
{
	page >>= PAGE_SHIFT;
	size_t i_idx = page / PAGES_PER_ENTRY;

	size_t bit_index = page % PAGES_PER_ENTRY;

	dma_mem_bitmap[i_idx] &= ~(1UL << bit_index);
}

void start_low_mem_allocator(struct bootmodule *initrd_module)
{
	for(size_t i = 0; i < BITMAP_SIZE; ++i)
	{
		dma_mem_bitmap[i] = 0xffffffffffffffff;
	}

	size_t entries = mmap_tag->size / mmap_tag->entry_size;
	struct multiboot_mmap_entry *mmap = (struct multiboot_mmap_entry *) mmap_tag->entries;
	size_t i = 0;

	for(; i < entries; i++, mmap++)
	{
		if(mmap->type != MULTIBOOT_MEMORY_AVAILABLE)
			continue;
		if(mmap->addr >= 0x1000000)
			break;

		if(mmap->addr == 0)
		{
			/* Page zero is reserved by the kernel */
			mmap->addr += PAGE_SIZE;
			mmap->len -= PAGE_SIZE;
		}

		size_t len = min(0x1000000 - mmap->addr, mmap->len);
		size_t pgs = len / PAGE_SIZE;
		mmap->len -= len;

		for(size_t i = 0; i < pgs; i++)
		{
			if(page_is_used((void *) (mmap->addr + i * PAGE_SIZE), initrd_module))
				continue;
			low_mem_allocator_clear(mmap->addr + i * PAGE_SIZE);
		}

		mmap->addr += len;
	}
}

size_t count_mem(void)
{
	size_t entries = mmap_tag->size / mmap_tag->entry_size;
	struct multiboot_mmap_entry *mmap = (struct multiboot_mmap_entry *) mmap_tag->entries;

	size_t memory = 0;

	for(size_t i = 0; i < entries; i++, mmap++)
	{
		if(mmap->type != MULTIBOOT_MEMORY_AVAILABLE)
			continue;
		memory += mmap->len;
		if(mmap->addr == 0)
		{
			mmap->addr += PAGE_SIZE;
			mmap->len -= PAGE_SIZE;
		}
	
		printf("MEMMAP [%llx - %llx]\n", mmap->addr, mmap->addr + mmap->len);
	}

	return memory;
}

unsigned long mb2_get_maxpfn(void)
{
	size_t entries = mmap_tag->size / mmap_tag->entry_size;
	struct multiboot_mmap_entry *mmap = (struct multiboot_mmap_entry *) mmap_tag->entries;

	size_t maxpfn = 0;

	for(size_t i = 0; i < entries; i++, mmap++)
	{
		if(mmap->type == MULTIBOOT_MEMORY_BADRAM || mmap->type == MULTIBOOT_MEMORY_RESERVED)
			continue;
		if(mmap->addr + mmap->len > maxpfn)
			maxpfn = mmap->addr + mmap->len;
	}

	printf("MAXPFN: %lx\n", maxpfn);
	return maxpfn >> PAGE_SHIFT;
}


void vterm_do_init(void);
void vm_print_map(void);

struct used_pages multiboot_struct_used;


void kernel_early(uintptr_t addr, uint32_t magic)
{
	addr += PHYS_BASE;
	if (magic != MULTIBOOT2_BOOTLOADER_MAGIC)
		return;
	idt_init();
	vm_init();

	struct multiboot_tag_framebuffer *tagfb = NULL;
	size_t total_mem = 0;
	unsigned long max_pfn = 0;

	struct multiboot_tag * tag;
	for(tag =
	     (struct multiboot_tag *)(addr + 8);
	     tag->type != MULTIBOOT_TAG_TYPE_END;
	     tag =
	     (struct multiboot_tag *) ((multiboot_uint8_t *) tag +
				       ((tag->size + 7) & ~7)))
		{
		switch (tag->type)
		{
		case MULTIBOOT_TAG_TYPE_MMAP:
		{
			mmap_tag = (struct multiboot_tag_mmap *) tag;
			total_mem = count_mem();
			max_pfn = mb2_get_maxpfn();
			break;
		}
		case MULTIBOOT_TAG_TYPE_FRAMEBUFFER:
		{
			tagfb = (struct multiboot_tag_framebuffer *) tag;
			break;
		}
		case MULTIBOOT_TAG_TYPE_MODULE:
		{
			initrd_tag = (struct multiboot_tag_module *) tag;
			break;
		}
		case MULTIBOOT_TAG_TYPE_ELF_SECTIONS:
		{
			secs = (struct multiboot_tag_elf_sections *) tag;
			break;
		}
		case MULTIBOOT_TAG_TYPE_CMDLINE:
		{
			struct multiboot_tag_string *t = (struct multiboot_tag_string *) tag;
			strcpy(get_kernel_cmdline(), t->string);
			break;
		}
		case MULTIBOOT_TAG_TYPE_ACPI_NEW:
		{
			struct multiboot_tag_new_acpi *acpi = (struct multiboot_tag_new_acpi *) tag;
			memcpy(&grub2_rsdp, &acpi->rsdp, sizeof(ACPI_TABLE_RSDP));
			break;
		}
		case MULTIBOOT_TAG_TYPE_ACPI_OLD:
		{
			struct multiboot_tag_old_acpi *acpi = (struct multiboot_tag_old_acpi *) tag;
			memcpy(&grub2_rsdp, &acpi->rsdp, sizeof(ACPI_TABLE_RSDP));
			break;
		}
		}
	}

	multiboot_struct_used.start = ((uintptr_t) addr - PHYS_BASE) & ~(PAGE_SIZE - 1);
	
	multiboot_struct_used.end = (uintptr_t) page_align_up((void *)((uintptr_t) tag - PHYS_BASE));
	multiboot_struct_used.next = NULL;
	page_add_used_pages(&multiboot_struct_used);

	elf_sections_reserve(secs);

	initrd.base = initrd_tag->mod_start;
	initrd.size = initrd_tag->mod_end - initrd_tag->mod_start;
	initrd.next = NULL;

	set_alloc_boot_page(multiboot2_alloc_boot_page);

	/* Identify the CPU it's running on (bootstrap CPU) */
	cpu_identify();
	paging_map_all_phys();

	set_initrd_address((void*) (uintptr_t) initrd_tag->mod_start);

	page_init(total_mem, max_pfn, multiboot2_get_phys_mem_region, &initrd);

	/* We need to get some early boot rtc data and initialize the entropy,
	 * as it's vital to initialize some entropy sources for the memory map
	*/
	early_boot_rtc();
	initialize_entropy();

	vm_late_init();

	paging_protect_kernel();
	
	if(tagfb)
	{
		init_multiboot2_framebuffer(tagfb);
	}

	vterm_do_init();

	init_elf_symbols(secs);

#ifdef CONFIG_KASAN
	kasan_init();
#endif
}

void reclaim_initrd(void)
{
	reclaim_pages(initrd.base, initrd.base + initrd.size);
}