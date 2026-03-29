/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _UAPI_EVDEV_H
#define _UAPI_EVDEV_H

#include <uapi/types.h>

struct input_id
{
    __u16 bustype;
    __u16 vendor;
    __u16 product;
    __u16 version;
};

#define ID_BUS     0
#define ID_VENDOR  1
#define ID_PRODUCT 2
#define ID_VERSION 3

#define BUS_PCI       0x01
#define BUS_ISAPNP    0x02
#define BUS_USB       0x03
#define BUS_HIL       0x04
#define BUS_BLUETOOTH 0x05
#define BUS_VIRTUAL   0x06

#define BUS_ISA         0x10
#define BUS_I8042       0x11
#define BUS_XTKBD       0x12
#define BUS_RS232       0x13
#define BUS_GAMEPORT    0x14
#define BUS_PARPORT     0x15
#define BUS_AMIGA       0x16
#define BUS_ADB         0x17
#define BUS_I2C         0x18
#define BUS_HOST        0x19
#define BUS_GSC         0x1A
#define BUS_ATARI       0x1B
#define BUS_SPI         0x1C
#define BUS_RMI         0x1D
#define BUS_CEC         0x1E
#define BUS_INTEL_ISHTP 0x1F
#define BUS_AMD_SFH     0x20
#define BUS_SDW         0x21

#define EVIOCGVERSION _IOR('E', 0x01, int)             /* get driver version */
#define EVIOCGID      _IOR('E', 0x02, struct input_id) /* get device ID */
#define EVIOCGREP     _IOR('E', 0x03, unsigned int[2]) /* get repeat settings */
#define EVIOCSREP     _IOW('E', 0x03, unsigned int[2]) /* set repeat settings */

#define EVIOCGKEYCODE    _IOR('E', 0x04, unsigned int[2]) /* get keycode */
#define EVIOCGKEYCODE_V2 _IOR('E', 0x04, struct input_keymap_entry)
#define EVIOCSKEYCODE    _IOW('E', 0x04, unsigned int[2]) /* set keycode */
#define EVIOCSKEYCODE_V2 _IOW('E', 0x04, struct input_keymap_entry)
#define EVIOCGKEY(len)   _IOC(_IOC_READ, 'E', 0x18, len) /* get global key state */

#define EVIOCGNAME(len) _IOC(_IOC_READ, 'E', 0x06, len) /* get device name */
#define EVIOCGPHYS(len) _IOC(_IOC_READ, 'E', 0x07, len) /* get physical location */
#define EVIOCGUNIQ(len) _IOC(_IOC_READ, 'E', 0x08, len) /* get unique identifier */
#define EVIOCGPROP(len) _IOC(_IOC_READ, 'E', 0x09, len) /* get device properties */
#define EVIOCGLED(len)  _IOC(_IOC_READ, 'E', 0x19, len)
#define EVIOCGSW(len)   _IOC(_IOC_READ, 'E', 0x1b, len)

#define EVIOCGBIT(ev, len) _IOC(_IOC_READ, 'E', 0x20 + (ev), len) /* get event bits */

#define EVIOCGRAB _IOW('E', 0x90, int)

#endif
