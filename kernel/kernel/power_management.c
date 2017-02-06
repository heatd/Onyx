/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <acpi.h>

#include <kernel/power_management.h>
#include <kernel/portio.h>
#include <kernel/acpi.h>
#include <kernel/panic.h>

void pm_reboot()
{
	if(ACPI_FAILURE(AcpiReset()))
		printf("ACPI reset failed, trying PS/2\n");
	outb(0x64, 0xFE);
	// If the reboot hasn't happened yet, load a zero-idt and interrupt
	__asm__ __volatile__("lidt 0x0");
	__asm__ __volatile__("cli; int $0x60");
	halt();
}
void pm_shutdown()
{
	acpi_shutdown(NULL);
}
void sys_reboot()
{
	pm_reboot();
}
void sys_shutdown()
{
	pm_shutdown();
}
void pm_init(void)
{
	AcpiEnableEvent(ACPI_EVENT_POWER_BUTTON, 0);
	AcpiInstallFixedEventHandler(ACPI_EVENT_POWER_BUTTON, acpi_shutdown, NULL);
}