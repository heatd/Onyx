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
__attribute__((format(printf, 3, 4))) int dev_printk(const char *log_lvl, const struct device *dev,
                                                     const char *fmt, ...);
__attribute__((format(printf, 3, 4))) int bus_printk(const char *log_lvl, const struct device *dev,
                                                     const char *fmt, ...);
__END_CDECLS

#define dev_emerg(dev, fmt, ...)  dev_printk(KERN_EMERG, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_alert(dev, fmt, ...)  dev_printk(KERN_ALERT, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_crit(dev, fmt, ...)   dev_printk(KERN_CRIT, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_err(dev, fmt, ...)    dev_printk(KERN_ERR, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_warn(dev, fmt, ...)   dev_printk(KERN_WARN, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_notice(dev, fmt, ...) dev_printk(KERN_NOTICE, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_info(dev, fmt, ...)   dev_printk(KERN_INFO, dev, dev_fmt(fmt), ##__VA_ARGS__)
#define dev_debug(dev, fmt, ...)  dev_printk(KERN_DEBUG, dev, dev_fmt(fmt), ##__VA_ARGS__)

#define bus_emerg(dev, fmt, ...)  bus_printk(KERN_EMERG, dev, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_alert(dev, fmt, ...)  bus_printk(KERN_ALERT, dev, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_crit(dev, fmt, ...)   bus_printk(KERN_CRIT, dev, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_err(dev, fmt, ...)    bus_printk(KERN_ERR, dev, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_warn(dev, fmt, ...)   bus_printk(KERN_WARN, dev, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_notice(dev, fmt, ...) bus_printk(KERN_NOTICE, dev, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_info(dev, fmt, ...)   bus_printk(KERN_INFO, dev, bus_fmt(fmt), ##__VA_ARGS__)
#define bus_debug(dev, fmt, ...)  bus_printk(KERN_DEBUG, dev, bus_fmt(fmt), ##__VA_ARGS__)

#endif
