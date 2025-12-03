#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H

#include <linux/wordpart.h>
#include <linux/kconfig.h>
#include <linux/string.h>

enum system_states {
	SYSTEM_BOOTING,
	SYSTEM_SCHEDULING,
	SYSTEM_FREEING_INITMEM,
	SYSTEM_RUNNING,
	SYSTEM_HALT,
	SYSTEM_POWER_OFF,
	SYSTEM_RESTART,
	SYSTEM_SUSPEND,
};
#define system_state SYSTEM_RUNNING
#define early_boot_irqs_disabled (false)

#define might_sleep() do {} while (0)
#define might_resched() do {} while (0)
#define cant_sleep() do {} while (0)

#endif
