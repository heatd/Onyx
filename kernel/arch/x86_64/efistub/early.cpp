/*
 * Copyright (c) 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <cpuid.h>

#include <onyx/compiler.h>
#include <onyx/vm.h>
#include <onyx/x86/control_regs.h>
#include <onyx/x86/msr.h>

#include <efi/boot-services.h>
#include <efi/efi.h>
#include <efi/runtime-services.h>
#include <efi/system-table.h>

#define BOOT_SECTION                                                                  \
    [[gnu::no_instrument_function, gnu::no_sanitize_address, gnu::no_sanitize_thread, \
      gnu::no_stack_protector, gnu::no_sanitize_undefined]]

extern char __kernel_size[];

extern "C" BOOT_SECTION void efi_relocate(EFI_SYSTEM_TABLE *table)
{
#if 0
    EFI_BOOT_SERVICES *bs = table->BootServices;
    EFI_PHYSICAL_ADDR addr;

    addr = UINT32_MAX;

    const size_t ksize = (size_t) &__kernel_size;
    auto pages = ksize >> PAGE_SHIFT;

    if (ksize & (PAGE_SIZE - 1))
        pages++;

    // bs->AllocatePages(AllocateMaxAddress, EfiReservedMemoryType, pages, )
#endif
}

BOOT_SECTION __always_inline bool efi_guids_equal(const EFI_GUID *a, const EFI_GUID *b)
{
    if (a->data1 != b->data1 || a->data2 != b->data2 || a->data3 != b->data3)
        return false;
    for (int i = 0; i < 8; i++)
    {
        if (a->data4[i] != b->data4[i])
            return false;
    }

    return true;
}

BOOT_SECTION static void efi_get_acpi_smbios_tables(EFI_SYSTEM_TABLE *st, const void **acpi_table,
                                                    const void **smbios_table,
                                                    const void **smbios30_table)
{
    EFI_GUID acpi_guid = ACPI_TABLE_GUID;
    EFI_GUID acpi20guid = ACPI_20_TABLE_GUID;
    EFI_GUID smbiosguid = SMBIOS_TABLE_GUID;
    EFI_GUID smbios3guid = SMBIOS3_TABLE_GUID;

    const auto entries = st->NumberOfTableEntries;

    for (size_t i = 0; i < entries; i++)
    {
        const auto guid = &st->ConfigurationTable[i].VendorGuid;
        const auto table = st->ConfigurationTable[i].VendorTable;
        if (efi_guids_equal(guid, &acpi_guid) || efi_guids_equal(guid, &acpi20guid))
            *acpi_table = table;
        else if (efi_guids_equal(guid, &smbiosguid))
            *smbios_table = table;
        else if (efi_guids_equal(guid, &smbios3guid))
            *smbios30_table = table;
    }
}

#define X86_PAGING_PRESENT      (1 << 0)
#define X86_PAGING_WRITE        (1 << 1)
#define X86_PAGING_USER         (1 << 2)
#define X86_PAGING_WRITETHROUGH (1 << 3)
#define X86_PAGING_PCD          (1 << 4)
#define X86_PAGING_ACCESSED     (1 << 5)
#define X86_PAGING_DIRTY        (1 << 6)
#define X86_PAGING_PAT          (1 << 7)
#define X86_PAGING_HUGE         (1 << 7)
#define X86_PAGING_GLOBAL       (1 << 8)
#define X86_PAGING_NX           (1UL << 63)

#define X86_PAGING_PROT_BITS ((PAGE_SIZE - 1) | X86_PAGING_NX)

#define LARGE2MB_SHIFT         21
#define PTE_INDEX(virt, level) ((((virt) >> 12) >> (((level) -1) * 9)) & 0x1ff)

static bool check_la57()
{
    u32 eax = 0;
    u32 ebx = 0;
    u32 ecx = 0;
    u32 edx = 0;

    eax = 7;
    if (!__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx))
    {
        // Is this even possible in long mode?
        return false;
    }

    // ECX[16] = LA57
    return ecx & (1 << 16);
}

BOOT_SECTION static void setup_mmu(PML *page_tables, unsigned long phys_base)
{
    constexpr unsigned long pt_flags = X86_PAGING_PRESENT | X86_PAGING_WRITE;

    // Enable NX
    u64 efer = rdmsr(IA32_EFER);
    efer |= IA32_EFER_NXE;
    wrmsr(IA32_EFER, efer);

    if (check_la57())
    {
        // Setup the PML5
        auto pml5 = page_tables++;
        auto pml4 = (unsigned long) (page_tables);
        pml5->entries[0] = pml4 | pt_flags;
        pml5->entries[PTE_INDEX(KERNEL_VIRTUAL_BASE, 5)] = pml4 | pt_flags;
    }

    auto pt = page_tables;
    auto next = page_tables + 1;

    pt->entries[0] = (unsigned long) next | pt_flags;
    pt->entries[PTE_INDEX(KERNEL_VIRTUAL_BASE, 4)] = (unsigned long) next | pt_flags;

    pt = next;
    next = page_tables + 2;

    // Lets treat pdlowers as a u64 array since they're 4 page directories in a row
    auto lower = (u64 *) (page_tables + 3);

    pt->entries[0] = (unsigned long) lower | pt_flags;
    pt->entries[PTE_INDEX(KERNEL_VIRTUAL_BASE, 3)] = (unsigned long) next | pt_flags;

    for (int i = 0; i < 2048; i++)
    {
        lower[i] = (i << LARGE2MB_SHIFT) | pt_flags | X86_PAGING_HUGE;
    }

    auto index = PTE_INDEX(KERNEL_VIRTUAL_BASE, 2);

    for (unsigned long i = index; i < 512; i++)
    {
        unsigned long theoretical = ((i - index) << LARGE2MB_SHIFT);
        next->entries[i] = (phys_base + theoretical) | pt_flags | X86_PAGING_HUGE;
    }
}

extern "C" void x86_efi_enable_57_mmu(PML *);

static void efi_switch_mmu(PML *page_tables)
{
    auto cr4 = x86_read_cr4();
    // Note: Some people in Tianocore thought it's a brilliant idea to break backwards compatibility
    // with everyone over the last 20 years, by adding PML5 support (behind a configuration knob).
    // This obviously breaks everyone using PML4 paging.
    // The simple case for us (here) is that indeed some genius in the firmware side enabled it,
    // and we do not have to drop into 32-bit to toggle it.
    // The hard case is when they haven't, and then we need to drop to 32-bit, disable paging,
    // toggle LA57, enable paging, jump back to 64-bit. Sucks.
    // But in reality, it's far better to have to drop back then to have broken firmware that
    // unilaterally breaks BACKWARDS COMPATIBILITY WITH THE LAST 20 YEARS OF BARE METAL EFI APPS AND
    // KERNELS.
    // More context: https://edk2.groups.io/g/devel/message/104422
    if (check_la57() && !(cr4 & CR4_LA57))
    {
        // We need to switch back to 32-bit, and then back to 64-bit... We need to do it in asm
        x86_efi_enable_57_mmu(page_tables);
    }
    else
        __asm__ __volatile__("mov %0, %%cr3" ::"r"(page_tables));
}

extern "C" void x86_efi_switch_tables();

efi_handoff_state efi_state;

extern "C" BOOT_SECTION void efi_handoff(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *systable,
                                         unsigned long phys_base, struct efi_handoff_state *state,
                                         PML *page_tables)
{
    auto bs = systable->BootServices;
    // Note: We must be careful when writing this code, as we may be running relocated into some
    // other physical address. (hence phys_base).
    EFI_MEMORY_DESCRIPTOR *memory_map = nullptr;
    size_t map_size;
    size_t map_key;
    size_t descriptor_size;
    u32 descriptor_version;
    const void *acpi_table = nullptr;
    const void *smbios_table = nullptr;

    // Lets get ACPI and SMBIOS tables from UEFI
    efi_get_acpi_smbios_tables(systable, &acpi_table, &smbios_table, &state->smbios30_table);

    state->acpi_table = acpi_table;
    state->smbios_table = smbios_table;

    map_size = 0;

    setup_mmu(page_tables, phys_base);

    // Finally, get the memory map
    do
    {
        EFI_STATUS st = bs->GetMemoryMap(&map_size, memory_map, &map_key, &descriptor_size,
                                         &descriptor_version);

        if (st == EFI_SUCCESS)
            break;

        // EfiLoaderData is the correct type here for UEFI apps. This will get
        // reserved later in kernel-proper EFI code.
        st = bs->AllocatePool(EfiLoaderData, map_size, (void **) &memory_map);

        if (st != EFI_SUCCESS)
        {
            systable->ConOut->OutputString(
                systable->ConOut,
                (char16_t *) u"error: Failed to allocate memory for the memory map");
            return;
        }
    } while (true);

    state->map_size = map_size;
    state->descriptor_size = descriptor_size;
    state->map_key = map_key;
    state->mmap = memory_map;
    state->descriptor_version = descriptor_version;

    // and exit boot services!
    EFI_STATUS st = bs->ExitBootServices(image_handle, map_key);

    if (st != EFI_SUCCESS)
        __asm__ __volatile__("int3");

    __asm__ __volatile__("cli");
    x86_efi_switch_tables();
    efi_switch_mmu(page_tables);
}
