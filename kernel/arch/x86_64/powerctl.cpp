/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdio.h>
#include <errno.h>

#include <onyx/cpu.h>
#include <onyx/log.h>
#include <onyx/panic.h>
#include <onyx/acpi.h>
#include <onyx/port_io.h>
#include <onyx/x86/idt.h>

enum
{
	REBOOT_STRATEGY_ACPI,
	REBOOT_STRATEGY_PS2,
	REBOOT_STRATEGY_TRIPLE_FAULT
};

/* TODO: Add EFI support */

extern "C"
int do_machine_reboot(unsigned int flags)
{
	INFO("do_machine_reboot", "Killing other CPUs");
	cpu_kill_other_cpus();

	/* Windows and Linux reboots retry a bunch of times;
	 * I don't think that whole thing should be needed these days, to be honest.
	 */

	unsigned int strategy = REBOOT_STRATEGY_ACPI;

	for(;;)
	{
		switch(strategy)
		{
			case REBOOT_STRATEGY_ACPI:
			{
				AcpiReset();

				strategy++;
				break;
			}

			case REBOOT_STRATEGY_PS2:
			{
				outb(0x64, 0xFE);
				strategy++;
				break;
			}

			case REBOOT_STRATEGY_TRIPLE_FAULT:
			{
				/* No way this won't fail. NULL is guaranteed to be unmapped and ud2 will cause a crash. */
				idt_ptr_t p;
				p.base = 0;
				p.limit = 0;

				idt_flush((uint64_t) &p);

				__asm__ __volatile__("ud2");

				__builtin_unreachable();
				break;
			}
		}
	}
}

extern "C"
int do_machine_shutdown(unsigned int flags)
{
	cpu_kill_other_cpus();

	/* acpi_shutdown() doesn't return on success */
	return acpi_shutdown() != AE_OK ? -EIO : 0;
}

extern "C"
int do_machine_halt(unsigned int flags)
{
	INFO("do_machine_halt", "Killing other CPUs");
	cpu_kill_other_cpus();

	halt();

	__builtin_unreachable();
}

extern "C"
int do_machine_suspend(unsigned int flags)
{
	return -EIO;
}
