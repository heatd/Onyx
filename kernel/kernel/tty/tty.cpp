/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
/**************************************************************************
 *
 *
 * File: tty.c
 *
 * Description: Contains the text terminal initialization and manipulation code
 *
 * Date: 30/1/2016
 *
 *
 **************************************************************************/

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>

#include <onyx/condvar.h>
#include <onyx/dev.h>
#include <onyx/framebuffer.h>
#include <onyx/id.h>
#include <onyx/init.h>
#include <onyx/mutex.h>
#include <onyx/panic.h>
#include <onyx/poll.h>
#include <onyx/port_io.h>
#include <onyx/process.h>
#include <onyx/serial.h>
#include <onyx/task_switching.h>
#include <onyx/tty.h>

#include <bits/ioctl.h>

void vterm_release_video(void *vterm);
void vterm_get_video(void *vt);

struct tty *main_tty = NULL;

struct ids *tty_ids;

int tty_add(struct tty *tty)
{
    struct tty **pp = &main_tty;

    while (*pp)
    {
        pp = &(*pp)->next;
    }

    *pp = tty;

    return 0;
}

void init_default_tty_termios(struct tty *tty)
{
    /* These defaults were mostly taken from the defaults that linux uses(seen with stty -a). */
    memset(&tty->term_io, 0, sizeof(struct termios));

    /* Docs source: https://man7.org/linux/man-pages/man3/termios.3.html */

    /* ICRNL - translate CR into NL ; IXON - Enable XON/XOFF flow control on output ; IUTF8 - Input
     * is UTF8 */
    tty->term_io.c_iflag = ICRNL | IXON | IUTF8;

    /* OPOST - Impl. defined output processing ; ONLCR - Map NL to CRNL ; All other flags are delay
     * masks of 0 */
    tty->term_io.c_oflag = OPOST | ONLCR | NL0 | CR0 | TAB0 | BS0 | VT0 | FF0;
    /* ISIG - Generate corresponding signals when specific characters are received.
     * ICANON - Enable canonical mode.
     * IEXTEN - Enable implementation defined input processing.
     * ECHO - Echo input characters.
     * ECHOE - if ICANON, the ERASE character erases the preceeding input character,
     *         and WERASE erases the preceeding word.
     * ECHOK - if ICANON, the KILL character erases the current line.
     * ECHOCTL - if ECHO is also set, special characters other than TAB, NL, START, STOP are echo'd
     * as ^X, where X is the character with ASCII code 0x40 greater than the special character.
     * ECHOKE - if ICANON, KILL is echoed by erasing each character on the line.
     *
     */
    tty->term_io.c_lflag = ISIG | ICANON | IEXTEN | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE;
    tty->term_io.c_cc[VINTR] = 003;
    tty->term_io.c_cc[VQUIT] = 034;
    tty->term_io.c_cc[VERASE] = '\x7f';
    tty->term_io.c_cc[VKILL] = 025;
    tty->term_io.c_cc[VEOF] = 004;
    tty->term_io.c_cc[VEOL] = tty->term_io.c_cc[VEOL2] = '\0';
    tty->term_io.c_cc[VTIME] = 0;
    tty->term_io.c_cc[VMIN] = 1;
    tty->term_io.c_cc[VSTART] = 021;
    tty->term_io.c_cc[VSTOP] = 023;
    tty->term_io.c_cc[VSUSP] = 032;
    tty->term_io.c_cc[VREPRINT] = 022;
    tty->term_io.c_cc[VDISCARD] = 017;
    tty->term_io.c_cc[VWERASE] = 027;
    tty->term_io.c_cc[VLNEXT] = 026;

    /* TODO: Properly implement this_ */
    tty->term_io.c_cflag = CS8 | B38400 | CREAD | HUPCL;
    tty->term_io.__c_ispeed = tty->term_io.__c_ospeed = 38400;

    tty->term_io.c_line = N_TTY;
}

extern struct tty_line_disc ntty_disc;

void tty_create_dev(tty *tty, const char *override_name = nullptr);
void tty_create_dev_console(tty *tty);

void tty_init(void *priv, void (*ctor)(struct tty *tty))
{
    if (!tty_ids)
    {
        tty_ids = idm_add("tty", 0, UINTMAX_MAX);

        assert(tty_ids != NULL);
    }

    struct tty *tty = (struct tty *) zalloc(sizeof(*tty));

    assert(tty != NULL);

    tty->priv = priv;
    mutex_init(&tty->lock);
    spinlock_init(&tty->input_lock);
    rwlock_init(&tty->termio_lock);
    tty->response = nullptr;

    tty->tty_num = idm_get_id(tty_ids);

    init_default_tty_termios(tty);

    tty->ldisc = &ntty_disc;

    init_wait_queue_head(&tty->read_queue);

    /** Use the ctor to init the tty */
    ctor(tty);

    tty_add(tty);

    printf("tty: Added tty%lu\n", tty->tty_num);
    tty_create_dev(tty);

    if (main_tty == tty)
    {
        // Create /dev/console for this tty
        tty_create_dev_console(tty);
    }
}

void cpu_kill_other_cpus(void);

void tty_write(const char *data, size_t size, struct tty *tty)
{
    if (mutex_owner(&tty->lock) == get_current_thread() && get_current_thread() != NULL)
    {
        tty->lock.counter = 0;
        cpu_kill_other_cpus();
        halt();
    }

    mutex_lock(&tty->lock);

    tty->ldisc->ops->write_out(data, size, tty);

    // Handle a pending response
    if (tty->response)
    {
        auto resp = tty->response;
        // We'll need to release the lock as tty_received_characters internal code locks the tty
        tty->response = nullptr;
        mutex_unlock(&tty->lock);
        tty_received_characters(tty, resp);
        free(resp);

        // Early return as to not double free the lock
        return;
    }

    mutex_unlock(&tty->lock);
}

void tty_received_character(struct tty *tty, char c)
{
    rw_lock_read(&tty->termio_lock);
    tty->ldisc->ops->receive_input(c, tty);
    rw_unlock_read(&tty->termio_lock);
}

void tty_received_characters(struct tty *tty, char *c)
{
    rw_lock_read(&tty->termio_lock);

    while (*c)
        tty->ldisc->ops->receive_input(*c++, tty);

    rw_unlock_read(&tty->termio_lock);
}

ssize_t __tty_has_input_available(struct tty *tty)
{
    bool is_canonical = TTY_LFLAG(tty, ICANON);

    for (size_t i = 0; i < tty->input_buf_pos; i++)
    {
        if (is_canonical && tty->input_buf[i] == '\n')
            return i + 1;

        if (tty->input_buf[i] == TTY_CC(tty, VEOF))
        {
            /* EOF, return here */
            return i + 1;
        }
    }

    return (is_canonical ? 0 : tty->input_buf_pos);
}

ssize_t tty_has_input_available(unsigned int flags, struct tty *tty)
{
    ssize_t ret = __tty_has_input_available(tty);
    return ret;
}

ssize_t tty_wait_for_line(unsigned int flags, struct tty *tty)
{
    spin_lock(&tty->input_lock);

    int res = -EWOULDBLOCK;

    if (flags & O_NONBLOCK && !tty_has_input_available(flags, tty))
        goto out_error;

    res = wait_for_event_locked_interruptible(&tty->read_queue, __tty_has_input_available(tty) != 0,
                                              &tty->input_lock);

    if (res < 0)
        goto out_error;

    return 0;
out_error:

    spin_unlock(&tty->input_lock);
    return res;
}

void tty_write_string(const char *data, struct tty *tty)
{
    tty_write(data, strlen(data), tty);
}

void tty_write_kernel(const char *data, size_t size)
{
    if (!main_tty)
        return;
    tty_write(data, size, main_tty);
}

void tty_write_string_kernel(const char *data)
{
    if (!main_tty)
        return;
    tty_write_string(data, main_tty);
}

size_t ttydevfs_write(size_t offset, size_t len, void *ubuffer, struct file *f)
{
    struct tty *tty = (struct tty *) f->f_ino->i_helper;

    char *buffer = (char *) malloc(len);
    if (!buffer)
        return (size_t) -ENOMEM;

    if (copy_from_user(buffer, ubuffer, len) < 0)
    {
        free(buffer);
        return -EFAULT;
    }

    tty_write(buffer, len, tty);
    return len;
}

size_t strnewlinelen(const char *str, unsigned int _len)
{
    size_t len = 0;
    for (; *str != '\n' && len != 0; ++str, _len--)
        ++len;
    return len + 1;
}

ssize_t tty_consume_input(void *ubuf, size_t len, size_t buflen, struct tty *tty)
{
    bool consuming_from_eof = tty->input_buf[buflen - 1] == TTY_CC(tty, VEOF);

    if (consuming_from_eof)
        buflen--;

    size_t to_read = min(len, buflen);

    if (copy_to_user(ubuf, tty->input_buf, to_read) < 0)
    {
        return -EFAULT;
    }

    size_t to_remove_from_buf = to_read;

    if (consuming_from_eof)
    {
        /* Discard the EOF character too */
        to_remove_from_buf++;
    }

    tty->input_buf_pos -= to_remove_from_buf;
    memcpy(tty->input_buf, tty->input_buf + to_remove_from_buf,
           sizeof(tty->input_buf) - to_remove_from_buf);

    return to_read;
}

size_t ttydevfs_read(size_t offset, size_t count, void *buffer, struct file *this_)
{
    struct tty *tty = (struct tty *) this_->f_ino->i_helper;

    int st = tty_wait_for_line(this_->f_flags, tty);

    if (st < 0)
        return (size_t) st;

    size_t len = __tty_has_input_available(tty);
    size_t read = tty_consume_input(buffer, count, len, tty);

    spin_unlock(&tty->input_lock);

    return read;
}

void tty_flush_input(struct tty *tty)
{
    spin_lock(&tty->input_lock);

    tty->input_buf_pos = 0;

    spin_unlock(&tty->input_lock);
}

unsigned int tty_tcsets(int req, struct tty *tty, struct termios *uterm)
{
    unsigned int ret = 0;

    rw_lock_write(&tty->termio_lock);

    if (req == TCSETSF)
        tty_flush_input(tty);

    ret = copy_from_user(&tty->term_io, uterm, sizeof(*uterm));

    rw_unlock_write(&tty->termio_lock);

    return ret;
}

unsigned int tty_do_tcflsh(struct tty *tty, int arg)
{
    if (arg == TCIFLUSH || arg == TCIOFLUSH)
        tty_flush_input(tty);

    return 0;
}

void tty_clear_session(tty *tty)
{
    tty->session->for_every_member(
        [](process *proc) -> void {
            scoped_lock g{proc->pgrp_lock};
            proc->ctty = nullptr;
        },
        PIDTYPE_SID);
}

void tty_set_ctty_unlocked(tty *tty)
{
    auto current = get_current_process();

    tty->session = current->session;
    tty->foreground_pgrp = current->process_group->get_pid();
    current->ctty = tty;
}

unsigned int do_tty_csctty(tty *tty, int force)
{
    scoped_mutex g2{tty->lock};
    auto current = get_current_process();

    if (force != 0 && force != 1)
        return -EINVAL;

    scoped_lock g{current->pgrp_lock};

    // The process must be a session leader
    if (!current->is_session_leader_unlocked())
        return -EPERM;

    // ...and not have a controlling terminal
    if (current->ctty)
        return -EPERM;

    if (tty->session)
    {
        if (force == 1 && is_root_user())
        {
            // If the terminal is already the ctty for a session, but we're forcing it and have
            // proper privs clear the tty from every process belonging to the session and steal it
            tty_clear_session(tty);
        }
        else
            return -EPERM;
    }

    tty_set_ctty_unlocked(tty);

    return 0;
}

dev_t ctty_dev = 0;

unsigned int do_tty_cnotty(tty *tty)
{
    scoped_mutex g{tty->lock};
    auto current = get_current_process();
    scoped_lock g2{current->pgrp_lock};

    // Nothing to do if we're not the ctty of the current process
    if (tty != current->ctty)
        return -ENOTTY;

    // If we're not the session leader, we just clear our own ctty
    // and return. Easy.
    if (!current->is_session_leader_unlocked())
    {
        current->ctty = nullptr;
        return 0;
    }
    else
    {
        // Get the tty's foreground pgrp and send SIGHUP + SIGCONT
        signal_kill_pg(SIGHUP, 0, nullptr, -tty->foreground_pgrp);
        signal_kill_pg(SIGCONT, 0, nullptr, -tty->foreground_pgrp);

        tty_clear_session(tty);
    }

    return 0;
}

unsigned int tty_ioctl(int request, void *argp, struct file *dev)
{
    struct tty *tty = (struct tty *) dev->f_ino->i_helper;

    unsigned int ret = 0;

    switch (request)
    {
        case TIOCSCTTY: {
            return do_tty_csctty(tty, (int) (unsigned long) argp);
        }

        case TIOCNOTTY: {
            if (dev->f_ino->i_dev != ctty_dev)
                return -ENOTTY;
            return do_tty_cnotty(tty);
        }

        case TCGETS: {
            rw_lock_read(&tty->termio_lock);

            struct termios *term = (termios *) argp;
            if (copy_to_user(term, &tty->term_io, sizeof(struct termios)) < 0)
                ret = -EFAULT;

            rw_unlock_read(&tty->termio_lock);

            return ret;
        }
        case TCSETS:
        case TCSETSW:
        case TCSETSF: {
            return tty_tcsets(request, tty, (termios *) argp);
        }

        case TCGETA:
        case TCSETA:
        case TCSETAW:
        case TCSETAF:
            return 0;
        case TIOCGLCKTRMIOS:
        case TIOCSLCKTRMIOS:
            return 0;
        case TIOCGWINSZ: {
            if (tty->ioctl)
                return tty->ioctl(request, argp, tty);
            return user_memset(argp, 0, sizeof(winsize));
        }
        case TIOCSWINSZ: {
            /* We don't support this_ yet */
            return 0;
        }
        case TCSBRK:
        case TCSBRKP:
        case TIOCSBRK:
        case TIOCCBRK:
            return 0;
        case TCXONC: {
            /* TODO */
            return 0;
        }
        case TIOCINQ: {
            int *arg = (int *) argp;
            if (copy_to_user(arg, (const void *) &tty->input_buf_pos, sizeof(int)) < 0)
                return -EFAULT;
            return 0;
        }
        case TIOONYXCTL: {
            int arg = (int) (unsigned long) argp;

            switch (arg)
            {
                case TIO_ONYX_GET_OWNERSHIP_OF_TTY:
                    /* Disable canon and echo */
                    tty->term_io.c_lflag &= ~(ICANON | ECHO);
                    if (tty->is_vterm)
                    {
                        vterm_release_video(tty->priv);
                    }
                    return 0;
                case TIO_ONYX_RELEASE_OWNERSHIP_OF_TTY: {
                    tty->term_io.c_lflag |= ICANON | ECHO;
                    if (tty->is_vterm)
                    {
                        vterm_get_video(tty->priv);
                    }
                    return 0;
                }
                default:
                    return -EINVAL;
            }
        }

        case TCFLSH:
            return tty_do_tcflsh(tty, (int) (unsigned long) argp);

        case TIOCSPGRP: {
            scoped_mutex g{tty->lock};
            auto pgrp = get_current_process()->process_group;
            tty->foreground_pgrp = pgrp->get_pid();
            return 0;
        }

        case TIOCGPGRP: {
            scoped_mutex g{tty->lock};
            return copy_to_user(argp, &tty->foreground_pgrp, sizeof(pid_t));
        }

        case TIOCGSID: {
            scoped_mutex g{tty->lock};
            auto session = tty->session;
            if (!session)
                return -ENOTTY;
            auto sid = session->get_pid();

            return copy_to_user(argp, &sid, sizeof(pid_t));
        }

        default:
            return -EINVAL;
    }
    return -EINVAL;
}

short tty_poll(void *poll_file, short events, struct file *f)
{
    struct tty *tty = (struct tty *) f->f_ino->i_helper;

    short revents = POLLOUT;

    if (events & POLLIN)
    {
        /* We lock termio for reading here because tty_has_input_available will touch the termio */
        rw_lock_read(&tty->termio_lock);

        spin_lock(&tty->input_lock);

        if (__tty_has_input_available(tty))
            revents |= POLLIN;
        else
            poll_wait_helper(poll_file, &tty->read_queue);

        spin_unlock(&tty->input_lock);

        rw_unlock_read(&tty->termio_lock);
    }

    return revents & events;
}

int ttyopen_try_to_set_ctty(tty *tty)
{
    auto current = get_current_process();
    scoped_lock g{current->pgrp_lock};

    if (current->is_session_leader_unlocked() && !current->ctty && !tty->session)
    {
        // If we're a session leader without a tty, and this tty has no session
        // set our ctty to this one
        tty_set_ctty_unlocked(tty);
    }

    return 0;
}

int ttydev_open(file *f)
{
    struct tty *tty = (struct tty *) f->f_ino->i_helper;
    scoped_mutex g{tty->lock};

    bool noctty = f->f_flags & O_NOCTTY;

    if (!noctty)
        return ttyopen_try_to_set_ctty(tty);

    return 0;
}

const struct file_ops tty_fops = {
    .read = ttydevfs_read,
    .write = ttydevfs_write,
    .ioctl = tty_ioctl,
    .on_open = ttydev_open,
    .poll = tty_poll,
};

void tty_create_dev(tty *tty, const char *override_name)
{
    char name[20];

    if (!override_name)
        sprintf(name, "tty%lu", tty->tty_num);
    else
        sprintf(name, "%s", override_name);

    auto ex = dev_register_chardevs(0, 1, 0, &tty_fops, name);
    if (ex.has_error())
        panic("Could not allocate a character device!\n");

    auto dev = ex.value();

    dev->private_ = tty;
    dev->show(0666);
}

int ctty_open(file *f);

const file_ops ctty_fops = {.on_open = ctty_open};

int ctty_open(file *f)
{
    auto current_process = get_current_process();
    scoped_lock g{current_process->pgrp_lock};

    if (!current_process->ctty)
    {
        return -EIO;
    }

    // Release the proper /dev/tty inode and replace it with a fake inode
    // that has the ctty's fops and private.
    // Note that we don't touch the dentry, so backtracking code will still find
    // /dev/tty as the path
    auto new_inode = inode_create(false);

    if (!new_inode)
        return -ENOMEM;

    new_inode->i_dev = f->f_ino->i_dev;
    new_inode->i_helper = current_process->ctty;
    new_inode->i_fops = (file_ops *) &tty_fops;

    inode_unref(f->f_ino);
    f->f_ino = new_inode;

    return 0;
}

int console_open(file *f)
{
    auto new_inode = inode_create(false);

    if (!new_inode)
        return -ENOMEM;

    new_inode->i_dev = f->f_ino->i_dev;
    new_inode->i_helper = f->f_ino->i_helper;
    new_inode->i_fops = (file_ops *) &tty_fops;

    inode_unref(f->f_ino);
    f->f_ino = new_inode;

    // Not great, but works!
    // /dev/console can never control a tty, so set O_NOCTTY temporarily
    int old_flags = f->f_flags;
    f->f_flags |= O_NOCTTY;

    int st = ttydev_open(f);
    f->f_flags = old_flags;

    return st;
}

const file_ops console_fops = {.on_open = console_open};

void tty_create_dev_console(tty *tty)
{
    // Creates /dev/console, which opens a console that *cannot* be a ctty
    auto ex = dev_register_chardevs(0, 1, 0, &console_fops, "console");
    if (ex.has_error())
        panic("Could not allocate a character device!\n");

    auto dev = ex.value();
    dev->private_ = (void *) tty;

    dev->show(0666);
}

void tty_create_dev_tty()
{
    // Creates /dev/tty, which opens the controlling terminal of the process
    auto ex = dev_register_chardevs(0, 1, 0, &ctty_fops, "tty");
    if (ex.has_error())
        panic("Could not allocate a character device!\n");

    auto dev = ex.value();
    ctty_dev = dev->dev();

    dev->show(0666);
}

INIT_LEVEL_CORE_INIT_ENTRY(tty_create_dev_tty);

/**
 * @brief Send a response to a command to the tty
 * Requires the internal tty lock to be held.
 * Limitation: Only one response can be sent per ->write().
 *
 * @param tty Pointer to the tty
 * @param str String of characters to send
 */
void tty_send_response(struct tty *tty, const char *str)
{
    // If we already have an active response, go away
    if (tty->response != nullptr)
        return;

    tty->response = strdup(str);

    if (!tty->response)
        return;
}

ssize_t kernel_console_write(const void *buffer, size_t size, struct tty *tty)
{
    platform_serial_write((const char *) buffer, size);
    return size;
}

static void kernel_console_ctor(struct tty *tty)
{
    // TODO: Determine the best console we have
    tty->write = kernel_console_write;
}
/**
 * @brief Create a kernel console tty
 *
 */
void console_init()
{
    tty_init(nullptr, kernel_console_ctor);
}
