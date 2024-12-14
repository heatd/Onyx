/*
 * Copyright (c) 2020 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <ctype.h>

#include <onyx/tty.h>

#include <uapi/ioctls.h>

static ssize_t n_tty_receive_input(char c, struct tty *tty);
static ssize_t n_tty_write_out(const char *s, size_t length, struct tty *tty);

const struct tty_ldisc_ops ntty_ops = {n_tty_receive_input, n_tty_write_out};

struct tty_line_disc ntty_disc = {.ldisc = N_TTY, .ops = &ntty_ops};
#define TTY_PRINT_IF_ECHO(c, l, t) \
    if (t->term_io.c_lflag & ECHO) \
    tty_write(c, l, t)

int iscntrl(int c)
{
    return (unsigned int) c < 0x20 || c == 0x7f || c == '\033';
}

struct tty_echo_args
{
    const char *to_echo;
    char inline_echo_buf[6];
    size_t len;
    bool ctl_echo_setup;
    bool do_not_print;
};

static inline bool should_print_special(char c)
{
    return c != '\t' && c != '\n' && c != '\021' && c != '\023' && c != '\x7f' && c != '\04';
}

void n_tty_receive_control_input(struct tty_echo_args *args, char c, struct tty *tty)
{
    if (c == TTY_CC(tty, VERASE))
    {
        if (tty->input_buf_pos <= 0)
        {
            args->to_echo = "";
            args->len = 0;
            tty->input_buf_pos = 0;
            return;
        }

        char old_char = tty->input_buf[tty->input_buf_pos - 1];

        tty->input_buf[tty->input_buf_pos - 1] = 0;
        tty->input_buf_pos--;
        args->to_echo = "\b \b";
        args->len = 3;
        tty->column--;

        if (TTY_LFLAG(tty, ECHOCTL) && iscntrl(old_char) && should_print_special(old_char))
        {
            args->to_echo = "\b \b\b \b";
            args->len = 6;
            tty->column -= 2;
        }
        else if (old_char == '\t')
        {
            // TODO: Erasing tabs is hard
            // n_tty_erase_tab(args, tty);
        }

        return;
    }

    if (c == TTY_CC(tty, VINTR))
    {
        if (tty->foreground_pgrp)
            signal_kill_pg(SIGINT, 0, nullptr, -tty->foreground_pgrp);
    }

    if (c == TTY_CC(tty, VSUSP))
    {
        if (tty->foreground_pgrp)
            signal_kill_pg(SIGTSTP, 0, nullptr, -tty->foreground_pgrp);
    }

    if (c == TTY_CC(tty, VQUIT))
    {
        if (tty->foreground_pgrp)
            signal_kill_pg(SIGQUIT, 0, nullptr, -tty->foreground_pgrp);
    }

    if (TTY_LFLAG(tty, ECHOCTL) && should_print_special(c))
    {
        args->inline_echo_buf[0] = '^';
        args->inline_echo_buf[1] = c + 0x40;
        args->to_echo = args->inline_echo_buf;
        args->len = 2;
        args->ctl_echo_setup = true;
    }

    if (c == TTY_CC(tty, VEOF))
        args->do_not_print = true;

    if (c != TTY_CC(tty, VINTR) && c != TTY_CC(tty, VKILL) && c != TTY_CC(tty, VQUIT) &&
        c != TTY_CC(tty, VSUSP))
        tty->input_buf[tty->input_buf_pos++] = c;
}

static ssize_t n_tty_receive_input(char c, struct tty *tty)
{
    struct tty_echo_args args;
    args.to_echo = &c;
    args.len = 1;
    args.ctl_echo_setup = false;
    args.do_not_print = false;

    if (TTY_IFLAG(tty, IGNCR) && c == '\r')
        return 0;

    mutex_lock(&tty->input_lock);

    if (TTY_IFLAG(tty, ICRNL) && c == '\r')
        c = '\n';

    if (2048 - tty->input_buf_pos == 0)
    {
        mutex_unlock(&tty->input_lock);
        return -ENOSPC;
    }

    if (iscntrl(c) && TTY_LFLAG(tty, ICANON))
        n_tty_receive_control_input(&args, c, tty);
    else
    {
        tty->input_buf[tty->input_buf_pos++] = c;
    }

    if (!TTY_LFLAG(tty, ICANON) || c == '\n' || c == TTY_CC(tty, VEOF))
    {
        tty->line_ready = true;
        wait_queue_wake_all(&tty->read_queue);
    }

    mutex_unlock(&tty->input_lock);

    if (TTY_LFLAG(tty, ECHO) && !args.do_not_print)
    {
        if (!iscntrl(c) || !should_print_special(c) || c == TTY_CC(tty, VERASE))
        {
            tty_write(args.to_echo, args.len, tty);
        }
        else if (args.ctl_echo_setup)
        {
            tty_write(args.to_echo, args.len, tty);
        }
    }

    return 0;
}

static ssize_t try_process_write(const char *s, size_t len, struct tty *tty)
{
    size_t i = 0;
    const char *buf = s;

    while (i < len)
    {
        char c = *s++;

        switch (c)
        {
            case '\r':
            case '\t':
            case '\n': {
                goto write_and_process;
            }
        }

        i++;
    }

write_and_process:
    if (i != 0)
        return tty->ops->write(buf, i, tty);
    else
        i = -EOPNOTSUPP;

    return i;
}

static size_t n_tty_output_char(char c, struct tty *tty, unsigned int write_room)
{
    switch (c)
    {
        case '\n': {
            if (TTY_OFLAG(tty, ONLCR))
            {
                tty->column = 0;
                if (write_room < 2)
                    return 0;
                return tty->ops->write("\r\n", 2, tty);
            }

            break;
        }

        case '\r': {
            if (TTY_OFLAG(tty, OCRNL))
            {
                c = '\n';
                break;
            }

            tty->column = 0;
            /* TODO: ONOCR, OLCUC */
            break;
        }

        case '\t': {
            unsigned int spaces = 8 - (tty->column & 7);

            if (TTY_OFLAG(tty, TABDLY) == TAB3)
            {
                // Convert tabs to spaces
                if (write_room < spaces)
                    return 0;
                return tty->ops->write("        ", spaces, tty);
            }

            tty->column += spaces;
            break; // fallthrough
        }
    }

    if (write_room == 0)
        return 0;
    return tty->ops->write(&c, 1, tty);
}

static size_t do_opost_write(const char *s, size_t length, struct tty *tty)
{
    size_t i = 0;
    unsigned int room;

    while (i < length)
    {
#if 0
        if (signal_is_pending())
            return i ?: -EINTR;
#endif
        ssize_t status = try_process_write(s + i, length - i, tty);
        if (status <= 0)
        {
            /* We repurpose EOPNOTSUPP for when we find a special processing char as the first byte
             * (i.e we wrote nothing), in order to distinguish from "ran out of write space" cases.
             */
            if (status == -EOPNOTSUPP)
                status = 0;
            else
                return status;
        }

        /* Try and send the largest string of characters that don't need output processing */
        i += status;

        tty->column += status;
        if (i != length)
        {
            room = tty_write_room(tty);
            if (n_tty_output_char(*(s + i), tty, room) == 0)
                break;
            i++;
        }
    }

    return i;
}

static ssize_t n_tty_write_out(const char *s, size_t length, struct tty *tty) REQUIRES(tty->lock)
{
    size_t i = 0;
    struct wait_queue_token token;
    init_wq_token(&token);
    token.thread = get_current_thread();

    while (i < length)
    {
#if 0
        if (signal_is_pending())
            return i ?: -EINTR;
#endif
        if (TTY_OFLAG(tty, OPOST))
            i += do_opost_write(s + i, length - i, tty);
        else
            i += tty->ops->write(s + i, length - i, tty);

        if (i == length)
            break;

        /* XXX A bunch of this needs to be fixed, properly. Thus the printk. */
        pr_warn("blocking with i %zu length %zu write room %u\n", i, length, tty_write_room(tty));
        set_current_state(THREAD_INTERRUPTIBLE);
        wait_queue_add(&tty->write_queue, &token);
        mutex_unlock(&tty->lock);

        sched_yield();

        mutex_lock(&tty->lock);
        wait_queue_remove(&tty->write_queue, &token);
    }

    return i;
}
