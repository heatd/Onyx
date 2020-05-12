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
#include <onyx/init.h>

void pm_reboot(void)
{
	if(ACPI_FAILURE(AcpiReset()))
		printf("ACPI reset failed, trying PS/2 controller\n");
	outb(0x64, 0xFE);
	// If the reboot hasn't happened yet, load a zero-idt and interrupt
	__asm__ __volatile__("lidt 0x0");
	__asm__ __volatile__("cli; int $0x60");
	halt();
}

void pm_do_shutdown(void)
{	
	bus_shutdown_every();

	acpi_shutdown(NULL);
}

unsigned int __pm_shutdown(void *context)
{
	pm_do_shutdown();

	return 0;
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

void pm_init(void)
{
	ACPI_STATUS st;
	
	if(ACPI_FAILURE((st = AcpiEnableEvent(ACPI_EVENT_POWER_BUTTON, 0))))
	{
		printf("AcpiEnableEvent failed!\n");
	}

	if(ACPI_FAILURE((st = AcpiInstallFixedEventHandler(ACPI_EVENT_POWER_BUTTON, __pm_shutdown, NULL))))
	{
		printf("AcpiInstallFixedEventHandler failed!\n");
	}

	if(ACPI_FAILURE((st = AcpiInstallFixedEventHandler(ACPI_EVENT_SLEEP_BUTTON, __pm_suspend, NULL))))
		printf("AcpiInstallFixedEventHandler failed!\n");
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(pm_init);
