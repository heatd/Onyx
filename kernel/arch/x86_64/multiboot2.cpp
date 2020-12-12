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
#include <onyx/x86/idt.h>
#include <onyx/tty.h>
#include <onyx/panic.h>
#include <onyx/cpu.h>
#include <onyx/vfs.h>
#include <onyx/initrd.h>
#include <onyx/task_switching.h>
#include <onyx/binfmt.h>
#include <onyx/elf.h>
#include <onyx/tss.h>
#include <onyx/heap.h>
#include <onyx/acpi.h>
#include <onyx/power_management.h>
#include <onyx/modules.h>
#include <onyx/random.h>
#include <onyx/dev.h>
#include <onyx/bootmem.h>
#include <onyx/log.h>
#include <onyx/process.h>
#include <onyx/block.h>
#include <onyx/elf.h>
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
#include <onyx/x86/kvm.h>
#include <onyx/x86/msr.h>
#include <onyx/x86/pat.h>

#include <drivers/rtc.h>

static struct multiboot_tag_module *initrd_tag = NULL;
struct multiboot_tag_elf_sections *secs;
struct multiboot_tag_mmap *mmap_tag = NULL;
ACPI_TABLE_RSDP grub2_rsdp = {0};
bool grub2_rsdp_valid = false;

extern "C"
uintptr_t get_rdsp_from_grub(void)
{
	if(grub2_rsdp_valid)
		return ((uintptr_t) &grub2_rsdp) - KERNEL_VIRTUAL_BASE;
	else
		return 0;
}

extern "C"
{

char *get_kernel_cmdline(void);
void set_initrd_address(void *initrd_address);

}

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

bool physical_mem_inited = false;

static inline void *temp_map_mem(unsigned long mem)
{
	if(physical_mem_inited)
		return PHYS_TO_VIRT(mem);
	else
		return x86_placement_map(mem);
}

extern "C"
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
	auto vmmap_tag = (multiboot_tag_mmap *) temp_map_mem((unsigned long) mmap_tag); 
	size_t entries = vmmap_tag->size / vmmap_tag->entry_size;
	size_t i = 0;

	for(; i < entries; i++)
	{
		auto phys_mmap = (struct multiboot_mmap_entry *) mmap_tag->entries + entries - 1 - i;
		auto mmap = (multiboot_mmap_entry *) x86_placement_map((unsigned long) phys_mmap);

		if(mmap->type != MULTIBOOT_MEMORY_AVAILABLE)
			continue;
	
		if(mmap->len >> PAGE_SHIFT >= nr_pages)
		{
			if(!range_is_used(mmap->addr, nr_pages))
			{
				uintptr_t ret = mmap->addr;
				mmap->addr += nr_pages << PAGE_SHIFT;
				mmap->len -= nr_pages << PAGE_SHIFT;
				//printf("allocated %lx\n", ret);
				return (void *) ret;
			}
			else if(!range_is_used(mmap->addr + mmap->len -
				(nr_pages << PAGE_SHIFT), nr_pages))
			{
				unsigned long ret = mmap->addr + mmap->len - (nr_pages << PAGE_SHIFT);
				mmap->len -= nr_pages << PAGE_SHIFT;
				//printf("allocated %lx\n", ret);
				return (void *) ret;
			}

		}
	}

	return NULL;
}

void *multiboot2_alloc_boot_page(size_t nr_pages, long flags)
{
	return multiboot2_alloc_boot_page_high(nr_pages);
}

void *multiboot2_get_phys_mem_region(uintptr_t *base,
	uintptr_t *size, void *context)
{
	/* Context holds an array index */

	auto tag = (multiboot_tag_mmap *) temp_map_mem((unsigned long) mmap_tag);
	size_t entries = tag->size / tag->entry_size;
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

static size_t mb2_count_mem(void)
{
	auto vmmap_tag = (multiboot_tag_mmap *) temp_map_mem((unsigned long) mmap_tag); 
	size_t entries = vmmap_tag->size / vmmap_tag->entry_size;

	size_t memory = 0;

	for(size_t i = 0; i < entries; i++)
	{
		auto mmap = (multiboot_mmap_entry *) x86_placement_map((unsigned long)(mmap_tag->entries + i));
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
	auto vmmap_tag = (multiboot_tag_mmap *) temp_map_mem((unsigned long) mmap_tag); 
	size_t entries = vmmap_tag->size / vmmap_tag->entry_size;
	struct multiboot_mmap_entry *phys_mmap = (struct multiboot_mmap_entry *) vmmap_tag->entries;

	size_t maxpfn = 0;

	for(size_t i = 0; i < entries; i++, phys_mmap++)
	{
		auto mmap = (multiboot_mmap_entry *) x86_placement_map((unsigned long) (mmap_tag->entries + i));

		if(mmap->type == MULTIBOOT_MEMORY_BADRAM || mmap->type == MULTIBOOT_MEMORY_RESERVED)
			continue;
		if(mmap->addr + mmap->len > maxpfn)
			maxpfn = mmap->addr + mmap->len;
	}

	printf("MAXPFN: %lx\n", maxpfn);
	return maxpfn >> PAGE_SHIFT;
}


extern "C"
void vterm_do_init(void);
void vm_print_map(void);

struct used_pages multiboot_struct_used;
struct multiboot_tag_efi64 efi64_mb2;
bool efi64_present = false;

extern "C"
void multiboot2_kernel_entry(uintptr_t addr, uint32_t magic)
{
	assert(magic == MULTIBOOT2_BOOTLOADER_MAGIC);

	/* First off, identify the CPU its running on */
	cpu_identify();

	idt_init();
	vm_init();

	struct multiboot_tag_framebuffer *tagfb = NULL;
	size_t total_mem = 0;
	unsigned long max_pfn = 0;

	struct multiboot_tag *tag;
	struct multiboot_tag *vtag;
	for(tag =
	     (struct multiboot_tag *)(addr + 8), vtag = (multiboot_tag *) x86_placement_map(addr + 8);
	     vtag->type != MULTIBOOT_TAG_TYPE_END;
	     tag =
	     (struct multiboot_tag *) ((multiboot_uint8_t *) tag +
				       ALIGN_TO(vtag->size, 8)),
				       vtag = (multiboot_tag *) x86_placement_map((unsigned long) tag))
	{
		switch (vtag->type)
		{
			case MULTIBOOT_TAG_TYPE_MMAP:
			{
				mmap_tag = (struct multiboot_tag_mmap *) tag;
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
				struct multiboot_tag_string *t = (struct multiboot_tag_string *) vtag;
				strcpy(get_kernel_cmdline(), t->string);
				break;
			}
			case MULTIBOOT_TAG_TYPE_ACPI_NEW:
			{
				struct multiboot_tag_new_acpi *acpi = (struct multiboot_tag_new_acpi *) vtag;
				memcpy(&grub2_rsdp, &acpi->rsdp, sizeof(ACPI_TABLE_RSDP));
				grub2_rsdp_valid = true;
				break;
			}
			case MULTIBOOT_TAG_TYPE_ACPI_OLD:
			{
				struct multiboot_tag_old_acpi *acpi = (struct multiboot_tag_old_acpi *) vtag;
				memcpy(&grub2_rsdp, &acpi->rsdp, sizeof(ACPI_TABLE_RSDP));
				grub2_rsdp_valid = true;
				break;
			}
			case MULTIBOOT_TAG_TYPE_EFI64:
			{
				efi64_present = true;
				memcpy(&efi64_mb2, vtag, sizeof(struct multiboot_tag_efi64));
				break;
			}
		}
	}

	total_mem = mb2_count_mem();
	max_pfn = mb2_get_maxpfn();

	multiboot_struct_used.start = ((uintptr_t) addr) & ~(PAGE_SIZE - 1);
	
	multiboot_struct_used.end = (uintptr_t) page_align_up((void *) tag);
	multiboot_struct_used.next = NULL;
	page_add_used_pages(&multiboot_struct_used);

	elf_sections_reserve(secs);

	auto vinitrd_tag = (multiboot_tag_module *) x86_placement_map((unsigned long) initrd_tag);
	initrd.base = vinitrd_tag->mod_start;
	initrd.size = vinitrd_tag->mod_end - vinitrd_tag->mod_start;
	initrd.next = NULL;

	set_alloc_boot_page(multiboot2_alloc_boot_page);

	pat_init();

	paging_map_all_phys();

	physical_mem_inited = true;

	set_initrd_address((void*) (uintptr_t) initrd.base);

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
		init_multiboot2_framebuffer((multiboot_tag_framebuffer *)
		                            x86_placement_map((unsigned long) tagfb));
	}

	vterm_do_init();

	init_elf_symbols(secs);

#ifdef CONFIG_KASAN
	kasan_init();
#endif
	/* TODO: Separate x86 specific initialization to another, boot protocol neutral, function */
	kvm_init();
}

extern "C"
void reclaim_initrd(void)
{
	reclaim_pages(initrd.base, initrd.base + initrd.size);
}
