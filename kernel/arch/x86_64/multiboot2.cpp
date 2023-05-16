/*
 * Copyright (c) 2018 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <errno.h>
#include <multiboot2.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include <onyx/acpi.h>
#include <onyx/binfmt.h>
#include <onyx/block.h>
#include <onyx/bootmem.h>
#include <onyx/clock.h>
#include <onyx/cmdline.h>
#include <onyx/cpu.h>
#include <onyx/crypt/sha256.h>
#include <onyx/debug.h>
#include <onyx/dev.h>
#include <onyx/driver.h>
#include <onyx/elf.h>
#include <onyx/framebuffer.h>
#include <onyx/heap.h>
#include <onyx/initrd.h>
#include <onyx/irq.h>
#include <onyx/log.h>
#include <onyx/mm/kasan.h>
#include <onyx/modules.h>
#include <onyx/page.h>
#include <onyx/pagecache.h>
#include <onyx/paging.h>
#include <onyx/panic.h>
#include <onyx/percpu.h>
#include <onyx/power_management.h>
#include <onyx/process.h>
#include <onyx/random.h>
#include <onyx/rwlock.h>
#include <onyx/serial.h>
#include <onyx/sysfs.h>
#include <onyx/task_switching.h>
#include <onyx/timer.h>
#include <onyx/tss.h>
#include <onyx/tty.h>
#include <onyx/utils.h>
#include <onyx/vdso.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>
#include <onyx/worker.h>
#include <onyx/x86/idt.h>
#include <onyx/x86/kvm.h>
#include <onyx/x86/msr.h>
#include <onyx/x86/pat.h>

#include <acpica/acpi.h>
#include <drivers/rtc.h>
#include <efi/efi.h>
#include <uapi/fcntl.h>

static struct multiboot_tag_module *initrd_tag;
struct multiboot_tag_elf_sections *secs;
struct multiboot_tag_mmap *mmap_tag;
struct multiboot_tag_framebuffer *tagfb;
acpi_table_rsdp grub2_rsdp = {};
bool grub2_rsdp_valid = false;

void set_initrd_address(void *initrd_address, size_t length);

static struct framebuffer fb = {.name = "multiboot2-fb"};

#define CALCULATE_MASK(shift, size) (((1 << size) - 1) << shift)
void init_multiboot2_framebuffer(struct multiboot_tag_framebuffer *tagfb)
{
    fb.framebuffer_phys = tagfb->common.framebuffer_addr;
    fb.height = tagfb->common.framebuffer_height;
    fb.width = tagfb->common.framebuffer_width;
    fb.bpp = tagfb->common.framebuffer_bpp;
    fb.pitch = tagfb->common.framebuffer_pitch;

    size_t framebuffer_size = fb.width * fb.height * (fb.bpp / CHAR_BIT);
    fb.framebuffer_size = framebuffer_size;

    fb.framebuffer =
        mmiomap((void *) fb.framebuffer_phys, framebuffer_size, VM_READ | VM_WRITE | VM_WC);

    if (!fb.framebuffer)
    {
        /* Err, I guess that we have no fb, so just ret */
        return;
    }

    fb.color.blue_shift = tagfb->framebuffer_blue_field_position;
    fb.color.green_shift = tagfb->framebuffer_green_field_position;
    fb.color.red_shift = tagfb->framebuffer_red_field_position;

    fb.color.blue_mask = CALCULATE_MASK(fb.color.blue_shift, tagfb->framebuffer_blue_mask_size);
    fb.color.green_mask = CALCULATE_MASK(fb.color.green_shift, tagfb->framebuffer_green_mask_size);
    fb.color.red_mask = CALCULATE_MASK(fb.color.red_shift, tagfb->framebuffer_red_mask_size);

    set_framebuffer(&fb);
}

bool physical_mem_inited = false;

static inline void *temp_map_mem(unsigned long mem)
{
    if (physical_mem_inited)
        return PHYS_TO_VIRT(mem);
    else
        return x86_placement_map(mem);
}

struct bootmodule initrd;

static size_t mb2_count_mem(void)
{
    auto vmmap_tag = (multiboot_tag_mmap *) temp_map_mem((unsigned long) mmap_tag);
    size_t entries = vmmap_tag->size / vmmap_tag->entry_size;

    size_t memory = 0;

    for (size_t i = 0; i < entries; i++)
    {
        auto mmap =
            (multiboot_mmap_entry *) x86_placement_map((unsigned long) (mmap_tag->entries + i));
        if (mmap->type != MULTIBOOT_MEMORY_AVAILABLE)
            continue;
        memory += mmap->len;
        if (mmap->addr == 0)
        {
            mmap->addr += PAGE_SIZE;
            mmap->len -= PAGE_SIZE;
        }

        printf("MEMMAP [%llx - %llx]\n", mmap->addr, mmap->addr + mmap->len);
        // Add memory as well

        bootmem_add_range(mmap->addr, mmap->len);
    }

    return memory;
}

unsigned long mb2_get_maxpfn(void)
{
    auto vmmap_tag = (multiboot_tag_mmap *) temp_map_mem((unsigned long) mmap_tag);
    size_t entries = vmmap_tag->size / vmmap_tag->entry_size;
    struct multiboot_mmap_entry *phys_mmap = (struct multiboot_mmap_entry *) vmmap_tag->entries;

    size_t maxpfn = 0;

    for (size_t i = 0; i < entries; i++, phys_mmap++)
    {
        auto mmap =
            (multiboot_mmap_entry *) x86_placement_map((unsigned long) (mmap_tag->entries + i));

        if (mmap->type == MULTIBOOT_MEMORY_BADRAM || mmap->type == MULTIBOOT_MEMORY_RESERVED)
            continue;
        if (mmap->addr + mmap->len > maxpfn)
            maxpfn = mmap->addr + mmap->len;
    }

    printf("MAXPFN: %lx\n", maxpfn);
    return maxpfn >> PAGE_SHIFT;
}

void vterm_do_init();

struct used_pages multiboot_struct_used;
struct multiboot_tag_efi64 efi64_mb2;
bool efi64_present = false;

static struct multiboot_tag_efi_mmap efi_mmap_tag;
static void *efi_mmap_ptr;
static bool efi_mmap_present = false;

static void x86_very_early_init()
{
    /* First off, identify the CPU its running on */
    cpu_identify();

    idt_init();
    vm_init();

    pat_init();

    platform_serial_init();
}

#define MULTIBOOT2_IGNORE_ACPI (1 << 0)

static void multiboot2_parse_tags(uintptr_t addr, unsigned int flags = 0)
{
    struct multiboot_tag *tag;
    struct multiboot_tag *vtag;
    for (tag = (struct multiboot_tag *) (addr + 8),
        vtag = (multiboot_tag *) x86_placement_map(addr + 8);
         vtag->type != MULTIBOOT_TAG_TYPE_END;
         tag = (struct multiboot_tag *) ((multiboot_uint8_t *) tag + ALIGN_TO(vtag->size, 8)),
        vtag = (multiboot_tag *) x86_placement_map((unsigned long) tag))
    {
        switch (vtag->type)
        {
            case MULTIBOOT_TAG_TYPE_MMAP: {
                mmap_tag = (struct multiboot_tag_mmap *) tag;
                break;
            }
            case MULTIBOOT_TAG_TYPE_FRAMEBUFFER: {
                tagfb = (struct multiboot_tag_framebuffer *) tag;
                break;
            }
            case MULTIBOOT_TAG_TYPE_MODULE: {
                initrd_tag = (struct multiboot_tag_module *) tag;
                break;
            }
            case MULTIBOOT_TAG_TYPE_ELF_SECTIONS: {
                secs = (struct multiboot_tag_elf_sections *) tag;
                break;
            }
            case MULTIBOOT_TAG_TYPE_CMDLINE: {
                struct multiboot_tag_string *t = (struct multiboot_tag_string *) vtag;
                set_kernel_cmdline(t->string);
                break;
            }
            case MULTIBOOT_TAG_TYPE_ACPI_NEW: {
                struct multiboot_tag_new_acpi *acpi = (struct multiboot_tag_new_acpi *) vtag;
                memcpy(&grub2_rsdp, &acpi->rsdp, sizeof(acpi_table_rsdp));
                grub2_rsdp_valid = true;
                break;
            }
            case MULTIBOOT_TAG_TYPE_ACPI_OLD: {
                struct multiboot_tag_old_acpi *acpi = (struct multiboot_tag_old_acpi *) vtag;
                memcpy(&grub2_rsdp, &acpi->rsdp, sizeof(acpi_table_rsdp));
                grub2_rsdp_valid = true;
                break;
            }
            case MULTIBOOT_TAG_TYPE_EFI64: {
                efi64_present = true;
                memcpy(&efi64_mb2, vtag, sizeof(struct multiboot_tag_efi64));
                break;
            }
            case MULTIBOOT_TAG_TYPE_EFI_MMAP: {
                efi_mmap_present = true;
                efi_mmap_ptr = ((multiboot_tag_efi_mmap *) tag)->efi_mmap;
                memcpy(&efi_mmap_tag, vtag, sizeof(struct multiboot_tag_efi_mmap));
                break;
            }
        }
    }

    if (!(flags & MULTIBOOT2_IGNORE_ACPI) && grub2_rsdp_valid)
        acpi_set_rsdp(((uintptr_t) &grub2_rsdp) - KERNEL_VIRTUAL_BASE + get_kernel_phys_offset());

    // Reserve all of multiboot2 tags
    bootmem_reserve(addr, (unsigned long) tag - addr);

    elf_sections_reserve(secs);

    auto vinitrd_tag = (multiboot_tag_module *) x86_placement_map((unsigned long) initrd_tag);
    initrd.base = vinitrd_tag->mod_start;
    initrd.size = vinitrd_tag->mod_end - vinitrd_tag->mod_start;
    initrd.next = nullptr;
    bootmem_reserve(initrd.base, initrd.size);

    set_initrd_address((void *) (uintptr_t) initrd.base, initrd.size);
}

static void x86_late_vm_init()
{
    /* We need to get some early boot rtc data and initialize the entropy,
     * as it's vital to initialize some entropy sources for the memory map
     */
    early_boot_rtc();
    initialize_entropy();

    vm_late_init();

    paging_protect_kernel();
}

static void mb2_init_fb()
{
    if (tagfb)
    {
        init_multiboot2_framebuffer(
            (multiboot_tag_framebuffer *) x86_placement_map((unsigned long) tagfb));
    }
}

static void x86_init_early_tail()
{
#ifdef CONFIG_KASAN
    kasan_init();
#endif
    kvm_init();
}

extern "C" void efi_entry_mb2(uintptr_t addr, EFI_SYSTEM_TABLE *system_table)
{
    x86_very_early_init();

    multiboot2_parse_tags(addr, MULTIBOOT2_IGNORE_ACPI);

    efi_boot_init(system_table);
    x86_late_vm_init();

    mb2_init_fb();

    vterm_do_init();
    init_elf_symbols(secs);

    efi_boot_late_init(system_table);

    x86_init_early_tail();
}

extern "C" void multiboot2_kernel_entry(uintptr_t addr, uint32_t magic)
{
    assert(magic == MULTIBOOT2_BOOTLOADER_MAGIC);

    x86_very_early_init();

    multiboot2_parse_tags(addr);

    size_t total_mem = 0;
    unsigned long max_pfn = 0;

    total_mem = mb2_count_mem();
    max_pfn = mb2_get_maxpfn();

    paging_map_all_phys();
    page_init(total_mem, max_pfn);
    x86_late_vm_init();

    mb2_init_fb();
    vterm_do_init();

    init_elf_symbols(secs);

#ifdef CONFIG_EFI
    if (efi64_present)
    {
        auto map_size = efi_mmap_tag.size - 20;
        efi_init((EFI_SYSTEM_TABLE *) PHYS_TO_VIRT(efi64_mb2.pointer),
                 (EFI_MEMORY_DESCRIPTOR *) PHYS_TO_VIRT(efi_mmap_ptr), map_size,
                 efi_mmap_tag.descr_size, efi_mmap_tag.descr_vers);
    }
#endif

    x86_init_early_tail();
}

void reclaim_initrd()
{
    reclaim_pages(initrd.base, initrd.base + initrd.size);
}
