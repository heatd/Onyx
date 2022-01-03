/*
 * Copyright (c) 2020 - 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_SERIAL_H
#define _ONYX_SERIAL_H

#include <stdint.h>

#include <onyx/wait_queue.h>
#include <onyx/tty.h>

class serial_port
{
private:
	unsigned int nr;

	/**
	 * @brief Allocates an index to the serial port,
	 *        so it can be used by i.e ttyS(N)
	 * 
	 * @return New index
	 */
	unsigned int allocate_serial_index();
protected:
	tty *tty_;
	/**
	 * @brief Sets the baud rate
	 * 
	 * @param rate Baud rate 
	 */
	virtual void set_baud_rate(uint16_t rate) = 0;

public:
	serial_port() : tty_{}
	{
		nr = allocate_serial_index();
	}

	/**
	 * @brief Initialises the serial port
	 * and creates the tty.
	 * 
	 * @return True on success, else false.
	 */
	bool init();
};

void platform_serial_init(void);
void platform_serial_write(const char *s, size_t size);

#endif
