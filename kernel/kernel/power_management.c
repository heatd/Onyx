/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <acpi.h>

#include <onyx/power_management.h>
#include <onyx/portio.h>
#include <onyx/acpi.h>
#include <onyx/panic.h>
#include <onyx/dev.h>
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
unsigned int __pm_shutdown(void *context)
{
	bus_shutdown_every();
	return acpi_shutdown(context);
}
unsigned int __pm_suspend(void *context)
{
	bus_suspend_every();
	return acpi_suspend(context);
}
void pm_shutdown(void)
{
	__pm_shutdown(NULL);
}
void sys_reboot(void)
{
	pm_reboot();
}
void sys_shutdown(void)
{
	pm_shutdown();
}
void pm_init(void)
{
	AcpiEnableEvent(ACPI_EVENT_POWER_BUTTON, 0);
	AcpiInstallFixedEventHandler(ACPI_EVENT_POWER_BUTTON, __pm_shutdown, NULL);
	AcpiInstallFixedEventHandler(ACPI_EVENT_SLEEP_BUTTON, __pm_suspend, NULL);
}
