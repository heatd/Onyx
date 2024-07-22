/*
 * Copyright (c) 2018 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/acpi.h>
#include <onyx/x86/platform_info.h>

void platform_init_acpi(void)
{
    acpi_table_fadt *fadt = &acpi_gbl_FADT;

    /* Detect certain features using the FADT */
    if (fadt->header.revision >= 2)
    {
        x86_platform.has_legacy_devices = (bool) (fadt->boot_flags & ACPI_FADT_LEGACY_DEVICES);
    }

    if ((fadt->header.revision >= 3) && x86_platform.i8042 != I8042_PLATFORM_ABSENT)
    {
        if (!(fadt->boot_flags & ACPI_FADT_8042))
            x86_platform.i8042 = I8042_FIRMWARE_ABSENT;
    }

    if (fadt->header.revision >= 4)
    {
        x86_platform.has_vga = (bool) !(fadt->boot_flags & ACPI_FADT_NO_VGA);
        x86_platform.has_msi = (bool) !(fadt->boot_flags & ACPI_FADT_NO_MSI);
    }

    if (fadt->header.revision >= 5)
    {
        x86_platform.has_rtc = (bool) !(fadt->boot_flags & ACPI_FADT_NO_CMOS_RTC);
    }
}
