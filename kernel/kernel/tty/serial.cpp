/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <onyx/dpc.h>
#include <onyx/serial.h>

#include <onyx/atomic.hpp>

static ssize_t serial_write_tty(const void *buffer, size_t size, struct tty *tty)
{
    serial_port *port = (serial_port *) tty->priv;
    return port->write_serial(buffer, size);
}

static atomic<unsigned int> serial_index = 0;

/**
 * @brief Allocates an index to the serial port,
 *        so it can be used by i.e ttyS(N)
 *
 * @return New index
 */
unsigned int serial_port::allocate_serial_index()
{
    return serial_index++;
}

static const struct tty_ops serial_port_ops = {
    .write = serial_write_tty,
};

/**
 * @brief Initialises the serial port
 * and creates the tty.
 *
 * @return True on success, else false.
 */
bool serial_port::init_tty()
{
    tty_init(
        this,
        [](struct tty *tty) {
            serial_port *port = (serial_port *) tty->priv;
            port->set_tty(tty);
            tty->ops = &serial_port_ops;
        },
        0);

    return true;
}

void serial_port::receive_byte(uint8_t data)
{
    tty_input_push_byte(tty_, data);
}
