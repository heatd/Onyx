#ifndef _ASM_IRQFLAGS_H
#define _ASM_IRQFLAGS_H

#include <onyx/irq.h>

#define arch_local_irq_enable()  irq_enable()
#define arch_local_irq_disable() irq_disable()

#define arch_local_irq_save()         irq_save_and_disable()
#define arch_local_irq_restore(flags) irq_restore(flags)
#define arch_irqs_disabled()          irq_is_disabled()
/* TODO: NOT x86 */
#define arch_irqs_disabled_flags(flags) (!((flags) & EFLAGS_INT_ENABLED))
#endif
