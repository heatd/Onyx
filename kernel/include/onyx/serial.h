/*
 * Copyright (c) 2020 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef _ONYX_SERIAL_H
#define _ONYX_SERIAL_H

#include <stdint.h>

#include <onyx/tty.h>
#include <onyx/wait_queue.h>

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
    spinlock bytebuf_lock;
    uint8_t byte_buf[100];
    size_t byte_buf_size;
    tty *tty_;
    /**
     * @brief Sets the baud rate
     *
     * @param rate Baud rate
     */
    virtual void set_baud_rate(uint16_t rate) = 0;

    /**
     * @brief Receives a byte and queues it for the rest of the kernel
     *
     * @param byte Byte of data to queue
     */
    void receive_byte(uint8_t byte);

public:
    serial_port() : tty_{}
    {
        nr = allocate_serial_index();
        spinlock_init(&bytebuf_lock);
    }

    void dispatch();

    /**
     * @brief Initialises the serial port
     * and creates the tty.
     *
     * @return True on success, else false.
     */
    bool init_tty();

    /**
     * @brief Set the tty
     *
     * @param tty Pointer to the tty
     */
    void set_tty(tty *tty)
    {
        tty_ = tty;
    }

    /**
     * @brief Write bytes to the serial port
     *
     * @param buffer Buffer
     * @param size Length
     * @return Positive byte count or negative error code
     */
    virtual ssize_t write_serial(const void *buffer, size_t size) = 0;
};

void platform_serial_init(void);
void platform_serial_write(const char *s, size_t size);

#endif
