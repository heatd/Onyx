/*
 * Copyright (c) 2016, 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_TTY_H
#define _ONYX_TTY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <termios.h>

#include <onyx/condvar.h>
#include <onyx/mutex.h>
#include <onyx/rwlock.h>
#include <onyx/wait_queue.h>

struct tty;

struct tty_ldisc_ops
{
    ssize_t (*receive_input)(char s, struct tty *tty);
    ssize_t (*write_out)(const char *s, size_t length, struct tty *tty);
};

struct tty_line_disc
{
    int ldisc;
    const struct tty_ldisc_ops *ops;
};

struct tty
{
    /* Read only members */
    ssize_t (*read)(void *buffer, size_t size, struct tty *tty);
    ssize_t (*write)(const void *buffer, size_t size, struct tty *tty);
    unsigned int (*ioctl)(int request, void *argp, struct tty *tty);
    void *priv;
    uintptr_t tty_num;
    struct tty_line_disc *ldisc;
    bool is_vterm;

    /* Read mostly */
    struct termios term_io;
    struct tty *next;

    /* Now, members that are frequently written to */
    struct mutex lock;
    struct rwlock termio_lock;
    unsigned int input_flags;
    bool line_ready;
    struct wait_queue read_queue;
    struct spinlock input_lock;
    char input_buf[2048];
    unsigned int input_buf_pos;

    char *response;

    pid_t foreground_pgrp;
};

#define TTY_OFLAG(tty, flag) ((tty)->term_io.c_oflag & flag)
#define TTY_CFLAG(tty, flag) ((tty)->term_io.c_cflag & flag)
#define TTY_LFLAG(tty, flag) ((tty)->term_io.c_lflag & flag)
#define TTY_IFLAG(tty, flag) ((tty)->term_io.c_iflag & flag)
#define TTY_CC(tty, c)       ((tty)->term_io.c_cc[c])

void tty_putchar(char c);
void tty_write(const char *data, size_t size, struct tty *tty);
void tty_write_string(const char *data, struct tty *tty);
void tty_write_kernel(const char *data, size_t size);
void tty_write_string_kernel(const char *data);
void tty_set_color(int color);
void tty_swap_framebuffers();
void tty_init(void *priv, void (*ctor)(struct tty *tty));
void tty_scroll();
void tty_put_entry_at(char c, uint32_t color, size_t column, size_t row);
void tty_received_character(struct tty *tty, char c);
void tty_received_characters(struct tty *tty, char *c);
void tty_create_dev();

/**
 * @brief Send a response to a command to the tty
 * Requires the internal tty lock to be held.
 * Limitation: Only one response can be sent per ->write().
 *
 * @param tty Pointer to the tty
 * @param str String of characters to send
 */
void tty_send_response(struct tty *tty, const char *str);

/**
 * @brief Create a kernel console tty
 *
 */
void console_init();

#define ANSI_ESCAPE_CODE           '\x1b'
#define DEC_CSI                    '#'
#define ANSI_CSI                   '['
#define ANSI_CURSOR_UP             'A'
#define ANSI_CURSOR_DOWN           'B'
#define ANSI_CURSOR_FORWARD        'C'
#define ANSI_CURSOR_BACK           'D'
#define CSI_VPA                    'd' // Vertical position absolute
#define CSI_VPR                    'e' // Vertical position relative
#define ANSI_CURSOR_NEXT_LINE      'E'
#define ANSI_CURSOR_PREVIOUS       'F'
#define ANSI_CURSOR_HORIZONTAL_ABS 'G'
#define ANSI_CURSOR_POS            'H'
#define ANSI_ERASE_IN_DISPLAY      'J'
#define ANSI_ERASE_IN_LINE         'K'
#define ANSI_SCROLL_UP             'S'
#define ANSI_SCROLL_DOWN           'T'
#define ANSI_HVP                   'f'
#define ANSI_SGR                   'm'
#define ANSI_SAVE_CURSOR           's'
#define ANSI_RESTORE_CURSOR        'u'
#define CSI_DELETE_CHARS           'P'
#define CSI_INSERT_BLANK           '@'
#define CSI_INSERT_LINE            'L'
#define CSI_DELETE_LINE            'M'
#define CSI_REP                    'b'
#define CSI_DEVICE_ATTRIBUTES      'c'
#define CSI_DEVICE_STATUS_REPORT   'n'
#define DEC_DECALN                 '8'

#define ANSI_SGR_RESET      0
#define ANSI_SGR_BOLD       1
#define ANSI_SGR_FAINT      2
#define ANSI_SGR_ITALIC     3
#define ANSI_SGR_UNDERLINE  4
#define ANSI_SGR_SLOWBLINK  5
#define ANSI_SGR_RAPIDBLINK 6
#define ANSI_SGR_REVERSE    7
#define ANSI_SGR_BLINKOFF   25
#define ANSI_SGR_SETFGMIN   30
#define ANSI_SGR_SETFGMAX   37
#define ANSI_SGR_DEFAULTFG  39
#define ANSI_SGR_SETBGMIN   40
#define ANSI_SGR_SETBGMAX   47
#define ANSI_SGR_DEFAULTBG  49

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#endif
