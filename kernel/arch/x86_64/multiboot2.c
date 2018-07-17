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
#include <onyx/vmm.h>
#include <onyx/paging.h>
#include <onyx/pmm.h>
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
#include <onyx/envp.h>
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

#include <drivers/rtc.h>

static struct multiboot_tag_module *initrd_tag = NULL;
struct multiboot_tag_elf_sections *secs;
struct multiboot_tag_mmap *mmap_tag = NULL;
uintptr_t grub2_rsdp = 0;

uintptr_t get_rdsp_from_grub(void)
{
	if(!grub2_rsdp)
		return 0;
	return grub2_rsdp - PHYS_BASE;
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

	fb.framebuffer = dma_map_range((void *) fb.framebuffer_phys,
		framebuffer_size, VM_WRITE | VM_NOEXEC | VM_GLOBAL);
	
	if(!fb.framebuffer)
	{
		/* Err, I guess that we have no console, so just hlt */
		__asm__ __volatile__("hlt");
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

void vterm_do_init(void);

void kernel_early(uintptr_t addr, uint32_t magic)
{
	addr += PHYS_BASE;
	if (magic != MULTIBOOT2_BOOTLOADER_MAGIC)
		return;
	idt_init();
	vmm_init();

	struct multiboot_tag_framebuffer *tagfb = NULL;
	size_t total_mem = 0;
	for (struct multiboot_tag * tag =
	     (struct multiboot_tag *)(addr + 8);
	     tag->type != MULTIBOOT_TAG_TYPE_END;
	     tag =
	     (struct multiboot_tag *) ((multiboot_uint8_t *) tag +
				       ((tag->size + 7) & ~7)))
		{
		switch (tag->type)
		{
		case MULTIBOOT_TAG_TYPE_BASIC_MEMINFO:
		{
			struct multiboot_tag_basic_meminfo *memInfo = (struct multiboot_tag_basic_meminfo *) tag;
			total_mem = memInfo->mem_lower + memInfo->mem_upper;
			break;
		}
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
			struct multiboot_tag_string *t = (struct multiboot_tag_string *) tag;
			strcpy(get_kernel_cmdline(), t->string);
			break;
		}
		case MULTIBOOT_TAG_TYPE_ACPI_NEW:
		{
			struct multiboot_tag_new_acpi *acpi = (struct multiboot_tag_new_acpi *) tag;
			grub2_rsdp = (uintptr_t) &acpi->rsdp;
			break;
		}
		case MULTIBOOT_TAG_TYPE_ACPI_OLD:
		{
			struct multiboot_tag_old_acpi *acpi = (struct multiboot_tag_old_acpi *) tag;
			grub2_rsdp = (uintptr_t) &acpi->rsdp;
			break;
		}
		}
	}

	bootmem_init(total_mem, (uintptr_t) &kernel_end);

	size_t entries = mmap_tag->size / mmap_tag->entry_size;
	struct multiboot_mmap_entry *mmap = (struct multiboot_mmap_entry *) mmap_tag->entries;

	for (size_t i = 0; i < entries; i++)
	{
		printf("Memory range %016llx - %016llx - type %u\n", mmap->addr,
		        mmap->addr + mmap->len, mmap->type);
		if (mmap->type == MULTIBOOT_MEMORY_AVAILABLE)
		{
			bootmem_push(mmap->addr, mmap->len, initrd_tag);
		}
		mmap++;
	}

	/* Identify the CPU it's running on (bootstrap CPU) */
	cpu_identify();
	paging_map_all_phys();

	mmap = (struct multiboot_mmap_entry *) mmap_tag->entries;
	set_initrd_address((void*) (uintptr_t) initrd_tag->mod_start);

	page_init();

	/* We need to get some early boot rtc data and initialize the entropy,
	 * as it's vital to initialize some entropy sources for the memory map
	*/
	early_boot_rtc();
	initialize_entropy();

	vmm_late_init();
	
	/* Register pages */
	page_register_pages();

	paging_protect_kernel();
	
	if(tagfb)
	{
		init_multiboot2_framebuffer(tagfb);

		vterm_do_init();
	}

	init_elf_symbols(secs);
}