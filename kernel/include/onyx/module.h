/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_MODULE_H
#define _ONYX_MODULE_H

#include <onyx/compiler.h>
#include <onyx/uname.h>

#define MODULE_LICENSE_GPL2 "GPL2"
#define MODULE_LICENSE_MIT  "MIT"
#define MODULE_LICENSE_BSD  "BSD"

#define MODULE_INFO(tag, x, name)                                                     \
    __attribute__((section(".modinfo"), used, aligned(1))) static const char __PASTE( \
        name, __COUNTER__)[] = tag "=" x

#define MODULE_AUTHOR(x)        MODULE_INFO("author", x, author)
#define MODULE_LICENSE(x)       MODULE_INFO("license", x, license)
#define MODULE_ALIAS(x)         MODULE_INFO("alias", x, alias)
#define MODULE_INSERT_VERSION() MODULE_INFO("kernel", OS_RELEASE_WITH_TAGS, kver)

#ifdef __KERNEL_MODULE__

#ifndef __cplusplus
#define MODULE_INIT(x) strong_alias(x, module_init)
#define MODULE_FINI(x) strong_alias(x, module_fini)

#else

#define MODULE_INIT(x)           \
    extern "C"                   \
    {                            \
    strong_alias(x, module_init) \
    }
#define MODULE_FINI(x)           \
    extern "C"                   \
    {                            \
    strong_alias(x, module_fini) \
    }

#endif

#else

#include <onyx/driver.h>

#define MODULE_INIT(x) DRIVER_INIT(x)
#define MODULE_FINI(x)

#endif
#endif
