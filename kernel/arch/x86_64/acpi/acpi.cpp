/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <onyx/acpi.h>

#include <onyx/x86/platform_info.h>

extern "C"
void platform_init_acpi(void)
{
	ACPI_TABLE_FADT *fadt = &AcpiGbl_FADT;

	/* Detect certain features using the FADT */
	if(fadt->Header.Revision >= 2)
	{
		x86_platform.has_legacy_devices = (bool) (fadt->BootFlags &
			ACPI_FADT_LEGACY_DEVICES);
	}

	if((fadt->Header.Revision >= 3) && x86_platform.i8042 !=
		I8042_PLATFORM_ABSENT)
	{
		if(!(fadt->BootFlags & ACPI_FADT_8042))
			x86_platform.i8042 = I8042_FIRMWARE_ABSENT;
	}

	if(fadt->Header.Revision >= 4)
	{
		x86_platform.has_vga = (bool) !(fadt->BootFlags &
			ACPI_FADT_NO_VGA);
		x86_platform.has_msi = (bool) !(fadt->BootFlags &
			ACPI_FADT_NO_MSI);
	}

	if(fadt->Header.Revision >= 5)
	{
		x86_platform.has_rtc = (bool) !(fadt->BootFlags &
			ACPI_FADT_NO_CMOS_RTC);
	}
}
