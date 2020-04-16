/*
* Copyright (c) 2020 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _ONYX_SERIAL_H
#define _ONYX_SERIAL_H

#include <stdint.h>

#include <onyx/wait_queue.h>

struct serial_port
{
	const char *name;
	struct wait_queue rcv_wait;
};

#ifdef __cplusplus
extern "C" {
#endif

struct serial_port *platform_get_main_serial(void);
void serial_write(const char *s, size_t size, struct serial_port *port);
void platform_serial_init(void);

#ifdef __cplusplus
}
#endif

#endif
