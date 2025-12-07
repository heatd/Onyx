#ifndef _LINUX_VGA_SWITCHEROO_H
#define _LINUX_VGA_SWITCHEROO_H

#include <linux/errno.h>
#include <linux/fb.h>

struct pci_dev;

static inline int vga_switcheroo_lock_ddc(struct pci_dev *dev)
{
    return -ENODEV;
}

static inline int vga_switcheroo_unlock_ddc(struct pci_dev *dev)
{
    return -ENODEV;
}

static inline void vga_switcheroo_process_delayed_switch(void)
{
}

#endif
