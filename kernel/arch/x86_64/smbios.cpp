/*
 * Copyright (c) 2016 - 2023 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <stdio.h>
#include <string.h>

#include <onyx/compiler.h>
#include <onyx/init.h>
#include <onyx/log.h>
#include <onyx/smbios.h>
#include <onyx/vm.h>

#include <efi/efi.h>

// TODO: Move this to generic code when the opportunity presents itself
// TODO: This code currently does not work properly (nr_structs not set, SMBIOS3.0 does not have
// it.)
static struct smbios_table *tables = nullptr;
static size_t nr_structs = 0;

#ifdef __x86_64__

static inline void *__find_phys_mem(void *lower_boundary, void *upper_boundary, int alignment,
                                    const char *s)
{
    for (size_t i = 0; i < ((uintptr_t) upper_boundary - (uintptr_t) lower_boundary) / alignment;
         i++)
    {
        if (!memcmp((void *) (((uintptr_t) lower_boundary + PHYS_BASE) + i * alignment), s,
                    strlen(s)))
        {
            return (void *) ((uintptr_t) lower_boundary + i * alignment);
        }
    }
    return nullptr;
}

/* Finds the 32-bit entry point */
static struct smbios_entrypoint32 *smbios_find_entry32()
{
    return (smbios_entrypoint32 *) __find_phys_mem((void *) 0xF0000, (void *) 0xFFFFF, 16, "_SM_");
}

/* Finds the 64-bit entrypoint */
static struct smbios_entrypoint64 *smbios_find_entry64()
{
    return (smbios_entrypoint64 *) __find_phys_mem((void *) 0xF0000, (void *) 0xFFFFF, 16, "_SM3_");
}

#endif

static unsigned long smbios_entry, smbios_entry64;

/**
 * @brief Set the tables for the SMBIOS subsystem.
 * If 0 is given, the table is ignored and not set.
 *
 * @param smbios_table SMBIOS entrypoint
 * @param smbios30_table SMBIOS30 entrypoint
 */
void smbios_set_tables(unsigned long smbios_table, unsigned long smbios30_table)
{
    if (smbios_table != 0)
        smbios_entry = smbios_table;
    if (smbios30_table != 0)
        smbios_entry64 = smbios30_table;
}

/* Finds the SMBIOS tables, independently of the entry point */
smbios_table *smbios_find_tables()
{
    struct smbios_entrypoint32 *entry32 = (struct smbios_entrypoint32 *) smbios_entry;
    struct smbios_entrypoint64 *entry64 = (struct smbios_entrypoint64 *) smbios_entry64;

    /* If any of them were not found, and this is an x86 BIOS system, try and scan for them.
     * EFI passes them directly, so what we have should already be set.
     */
#ifdef __x86_64__
    if (!efi_enabled())
    {
        if (!entry32)
            entry32 = smbios_find_entry32();

        if (!entry64)
            entry64 = smbios_find_entry64();
    }
#endif

    if (entry64)
    {
        LOG("smbios", "64-bit table: %p\n", entry64);

        entry64 = (struct smbios_entrypoint64 *) ((char *) entry64 + PHYS_BASE);

        return (smbios_table *) PHYS_TO_VIRT(entry64->addr);
    }

    if (entry32)
    {
        LOG("smbios", "32-bit table: %p\n", entry32);

        /* Find the address and the size of the tables */

        entry32 = (struct smbios_entrypoint32 *) ((char *) entry32 + PHYS_BASE);

        return (smbios_table *) PHYS_TO_VIRT(entry32->addr);
    }

    return nullptr;
}

struct smbios_table *smbios_get_table(int type)
{
    if (!tables)
        return nullptr;
    struct smbios_table *tab = tables;
    for (size_t i = 0; i < nr_structs; i++)
    {
        if (tab->type == type)
            return tab;
        char *a = (char *) tab + tab->len;
        uint16_t zero = 0;
        while (memcmp(a, &zero, 2))
        {
            a++;
        }
        a += 2;
        tab = (struct smbios_table *) a;
    }
    return nullptr;
}

char *smbios_get_string(struct smbios_table *t, uint8_t strndx)
{
    char *strtab = ((char *) t + t->len);
    uint8_t i = 0;
    while (i != strndx - 1)
    {
        strtab += strlen(strtab) + 1;
        i++;
    }
    return strtab;
}

/* Initializes the smbios */
void smbios_init()
{
    LOG("smbios", "Initializing!\n");

    tables = smbios_find_tables();
    if (!tables)
        return;

    struct smbios_table_bios_info *info =
        (struct smbios_table_bios_info *) smbios_get_table(SMBIOS_TYPE_BIOS_INFO);

    if (info)
    {
        INFO("smbios", "BIOS Vendor: %s\n", smbios_get_string(&info->header, info->vendor));
        INFO("smbios", "BIOS Date: %s\n",
             smbios_get_string(&info->header, info->bios_release_date));
    }
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(smbios_init);
