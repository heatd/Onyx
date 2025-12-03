#ifndef _LINUX_INTERRUPT_H
#define _LINUX_INTERRUPT_H

#include <onyx/irq.h>

#define in_interrupt() (is_in_interrupt())

#endif
