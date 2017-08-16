/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _KERNEL_MODULE_H_INCLUDED
#define _KERNEL_MODULE_H_INCLUDED

#include <kernel/kernelinfo.h>
#define MODULE_LICENSE_GPL2 	"GPL2"
#define MODULE_LICENSE_MIT	"MIT"
#define MODULE_LICENSE_BSD	"BSD"

#define ___PASTE(a,b) a##b
#define __PASTE(a,b) ___PASTE(a,b)

#define MODULE_INFO(tag, x, name) __attribute__((section(".modinfo"), used, aligned(1))) const char __PASTE(name, __COUNTER__) [] = tag "=" x

#define MODULE_AUTHOR(x) MODULE_INFO("author", x, author)
#define MODULE_LICENSE(x) MODULE_INFO("license", x, license)
#define MODULE_ALIAS(x) MODULE_INFO("alias", x, alias)
#define MODULE_INSERT_VERSION() MODULE_INFO("kernel", OS_RELEASE, kver) 

#endif
