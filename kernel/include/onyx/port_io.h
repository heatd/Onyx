/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _ONYX_PORT_IO_H
#define _ONYX_PORT_IO_H

#ifdef __x86_64__
#include <onyx/x86/port_io.h>
#else
#include <onyx/no_port_io.h>
#endif

#endif
