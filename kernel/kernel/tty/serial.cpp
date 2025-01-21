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

void serial_port::dispatch()
{
    char temp[100];
    size_t len = 0;

    {
        scoped_lock<spinlock, true> g{bytebuf_lock};
        memcpy(temp, byte_buf, byte_buf_size);
        len = byte_buf_size;
        byte_buf_size = 0;
    }

    for (size_t i = 0; i < len; i++)
    {
        tty_received_character(tty_, temp[i]);
    }
}

void do_dispatch(void *ctx)
{
    serial_port *port = (serial_port *) ctx;
    port->dispatch();
}

void serial_port::receive_byte(uint8_t data)
{
    scoped_lock<spinlock, true> g{bytebuf_lock};
    if (byte_buf_size < sizeof(byte_buf))
    {
        // TODO: This doesn't work if we overflow the buffer.
        // Ring buffer?
        byte_buf[byte_buf_size++] = data;
    }

    struct dpc_work work;
    work.context = (void *) this;

    work.funcptr = do_dispatch;

    dpc_schedule_work(&work, DPC_PRIORITY_HIGH);
}
