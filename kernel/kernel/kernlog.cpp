/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/log.h>
#include <onyx/panic.h>
#include <onyx/timer.h>
#include <onyx/vm.h>

#include "onyx/serial.h"

#ifdef __x86_64__
#define VBOX_DEBUG
#endif

#ifdef VBOX_DEBUG
#include <onyx/port_io.h>
#endif

USED char _log_buf[LOG_BUF_SIZE];
USED size_t log_position = 0;

void kernlog_print(const char *msg)
{

#ifdef VBOX_DEBUG
    const char *m = msg;
    while (*m)
    {
        outb(0x504, *m);
        m++;
    }
#endif

    const auto nanoseconds = clocksource_get_time();
    const auto seconds = nanoseconds / NS_PER_SEC;
    const auto milis = (nanoseconds % NS_PER_SEC) / NS_PER_MS;
    if (log_position + strlen(msg) + 13 + 1 <= LOG_BUF_SIZE)
    {
        /* If there's clearly enough space, it's straight forward to do */
        /* Compose a message containing a timestamp */
        /* TODO: This strlen(msg) + 13 + 2 math is off */
        memset(&_log_buf[log_position], 0, strlen(msg) + 13 + 2);
        snprintf(&_log_buf[log_position], 200, "[%05lu.%05lu] %s", seconds, milis, msg);
        log_position += strlen(msg) + 13 + 1;
    }
    else
    {
        /* else start overwriting the buffer head */
        log_position = 0;
        snprintf(&_log_buf[log_position], 200, "[%lu.%lu] %s", seconds, milis, msg);
        log_position += strlen(msg) + 13 + 1;
    }
}

void kernlog_clear(void)
{
    memset(_log_buf, 0, LOG_BUF_SIZE);
    log_position = 0;
}

#define SYSLOG_ACTION_READ        2
#define SYSLOG_ACTION_READ_CLEAR  4
#define SYSLOG_ACTION_CLEAR       5
#define SYSLOG_ACTION_SIZE_BUFFER 10

int sys_syslog(int type, char *buffer, int len)
{
    if (type == SYSLOG_ACTION_SIZE_BUFFER)
        return (int) log_position;
    switch (type)
    {
        case SYSLOG_ACTION_READ: {
            if (copy_to_user(buffer, _log_buf, len) < 0)
                return -EFAULT;
            break;
        }
        case SYSLOG_ACTION_READ_CLEAR: {
            if (copy_to_user(buffer, _log_buf, len) < 0)
                return -EFAULT;
            kernlog_clear();
            break;
        }
        case SYSLOG_ACTION_CLEAR: {
            kernlog_clear();
            break;
        }
    }
    return 0;
}

void kernlog_dump(void)
{
    printk("%s\n", _log_buf);
}

static unsigned int log_level = LOG_LEVEL_ERROR | LOG_LEVEL_WARNING | LOG_LEVEL_FATAL;

void kernlog_set_log_level(unsigned int level)
{
    log_level = level;
}

void kernlog_send(unsigned int level, const char *msg, ...)
{
    if (log_level & level)
    {
        va_list va;
        va_start(va, msg);
        vprintf(msg, va);
        va_end(va);
    }
}
