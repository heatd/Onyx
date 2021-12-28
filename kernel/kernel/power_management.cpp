/*
* Copyright (c) 2016-2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <onyx/power_management.h>
#include <onyx/port_io.h>
#include <onyx/acpi.h>
#include <onyx/panic.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/cred.h>
#include <onyx/public/power_management.h>
#include <onyx/mm/flush.h>

extern "C"
{

int do_machine_reboot(unsigned int flags);
int do_machine_shutdown(unsigned int flags);
int do_machine_halt(unsigned int flags);
int do_machine_suspend(unsigned int flags);

}

/* Note that this is in a specific order that reflects POWER_STATE_*, don't change this. */
int (*powerctl_table[])(unsigned int flags) =
{
	do_machine_reboot,
	do_machine_shutdown,
	do_machine_halt,
	do_machine_suspend
};

int do_powerctl(unsigned int state, unsigned int flags)
{
	if(!(flags & POWER_STATE_FLAG_NO_SYNC))
		flush_do_sync();

	/* bus_shutdown_every works for every power state except suspend. */
	if(state == POWER_STATE_SUSPEND)
		bus_suspend_every();
	else
		bus_shutdown_every();

	return powerctl_table[state](flags);
}

int set_power_state(unsigned int state, unsigned int flags)
{
	switch(state)
	{
		case POWER_STATE_REBOOT:
		case POWER_STATE_HALT:
		case POWER_STATE_SUSPEND:
		case POWER_STATE_SHUTDOWN:
			return do_powerctl(state, flags);
		default:
			return -EINVAL;
	}
}

#define VALID_SET_POWER_STATE_FLAGS POWER_STATE_FLAG_NO_SYNC

int sys_set_power_state(unsigned int state, unsigned int flags)
{
	auto c = creds_get();
	bool is_root = c->euid == 0;
	creds_put(c);

	if(!is_root)
		return -EPERM;

	if(flags & ~VALID_SET_POWER_STATE_FLAGS)
		return -EINVAL;

	return set_power_state(state, flags);
}
