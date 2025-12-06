/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_DEV_PRINTK_H
#define _ONYX_DEV_PRINTK_H

#include <onyx/compiler.h>

struct device;

#ifndef dev_fmt
#define dev_fmt(fmt) fmt
#endif

#ifndef bus_fmt
#define bus_fmt(fmt) fmt
#endif

__BEGIN_CDECLS
__attribute__((format(printf, 3, 4))) int dev_printk(struct device *dev, const char *log_lvl,
                                                     const char *fmt, ...);
__attribute__((format(printf, 3, 4))) int bus_printk(struct device *dev, const char *log_lvl,
                                                     const char *fmt, ...);
__END_CDECLS

#define dev_emerg(dev, fmt, ...)  dev_printk(dev, KERN_EMERG, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_alert(dev, fmt, ...)  dev_printk(dev, KERN_ALERT, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_crit(dev, fmt, ...)   dev_printk(dev, KERN_CRIT, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_err(dev, fmt, ...)    dev_printk(dev, KERN_ERR, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_warn(dev, fmt, ...)   dev_printk(dev, KERN_WARN, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_notice(dev, fmt, ...) dev_printk(dev, KERN_NOTICE, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_info(dev, fmt, ...)   dev_printk(dev, KERN_INFO, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_debug(dev, fmt, ...)  dev_printk(dev, KERN_DEBUG, dev_fmt(fmt), ##__VA_ARGS__)

#define bus_emerg(dev, fmt, ...)  bus_printk(dev, KERN_EMERG, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_alert(dev, fmt, ...)  bus_printk(dev, KERN_ALERT, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_crit(dev, fmt, ...)   bus_printk(dev, KERN_CRIT, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_err(dev, fmt, ...)    bus_printk(dev, KERN_ERR, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_warn(dev, fmt, ...)   bus_printk(dev, KERN_WARN, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_notice(dev, fmt, ...) bus_printk(dev, KERN_NOTICE, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_info(dev, fmt, ...)   bus_printk(dev, KERN_INFO, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_debug(dev, fmt, ...)  bus_printk(dev, KERN_DEBUG, bus_fmt(fmt), ##__VA_ARGS__)

#endif
