/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
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
#include <uapi/fcntl.h>

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

/**
 * @brief Create a TTY device
 *
 * @param priv Private data for the tty
 * @param ctor Constructor for the tty (runs while inside tty_init)
 * @param flags Flags
 * @return A pointer to a strict tty, or NULL
 */
struct tty *tty_init(void *priv, void (*ctor)(struct tty *tty), unsigned int flags)
{
    if (!tty_ids)
    {
        tty_ids = idm_add("tty", 0, UINTMAX_MAX);

        assert(tty_ids != NULL);
    }

    struct tty *tty = (struct tty *) zalloc(sizeof(*tty));
    // TODO: Update callers to handle OOM. Until then, we have this DoS vector.

    assert(tty != NULL);

    tty->priv = priv;
    mutex_init(&tty->lock);
    mutex_init(&tty->input_lock);
    rwlock_init(&tty->termio_lock);
    tty->response = nullptr;

    tty->tty_num = idm_get_id(tty_ids);

    init_default_tty_termios(tty);

    tty->ldisc = &ntty_disc;

    init_wait_queue_head(&tty->read_queue);
    init_wait_queue_head(&tty->write_queue);

    /** Use the ctor to init the tty */
    if (ctor)
        ctor(tty);

    tty_add(tty);

    if (!(flags & TTY_INIT_PTY))
    {
        printf("tty: Added tty%lu\n", tty->tty_num);
        tty_create_dev(tty);
    }

    if (main_tty == tty)
    {
        // Create /dev/console for this tty
        tty_create_dev_console(tty);
    }

    return tty;
}

ssize_t tty_write(const char *data, size_t size, struct tty *tty)
{
    ssize_t err = 0;
    mutex_lock(&tty->lock);
    err = tty->ldisc->ops->write_out(data, size, tty);

    // Handle a pending response
    if (tty->response)
    {
        char *resp = tty->response;
        // We'll need to release the lock as tty_received_characters internal code locks the tty
        tty->response = nullptr;
        mutex_unlock(&tty->lock);
        tty_received_characters(tty, resp);
        free(resp);

        // Early return as to not double-release the lock
        return err;
    }

    mutex_unlock(&tty->lock);
    return err;
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

ssize_t tty_received_buf(struct tty *tty, const char *c, size_t len)
{
    size_t i;
    rw_lock_read(&tty->termio_lock);

    for (i = 0; i < len; i++)
    {
        if (tty->ldisc->ops->receive_input(*c++, tty) == -ENOSPC)
            break;
    }

    rw_unlock_read(&tty->termio_lock);
    return i;
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

ssize_t tty_wait_for_line(unsigned int flags, struct tty *tty) TRY_ACQUIRE(0, tty->input_lock)
{
    mutex_lock(&tty->input_lock);

    int res = -EWOULDBLOCK;

    if (flags & O_NONBLOCK && !tty_has_input_available(flags, tty))
        goto out_error;

    res = wait_for_event_mutex_interruptible(&tty->read_queue, __tty_has_input_available(tty) != 0,
                                             &tty->input_lock);

    if (res < 0)
        goto out_error;

    return 0;
out_error:

    mutex_unlock(&tty->input_lock);
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

    len = tty_write(buffer, len, tty);
    free(buffer);
    return len;
}

size_t strnewlinelen(const char *str, unsigned int _len)
{
    size_t len = 0;
    for (; *str != '\n' && len != 0; ++str, _len--)
        ++len;
    return len + 1;
}

void tty_finish_read(struct tty *tty)
{
    if (tty->ops->finish_read)
        tty->ops->finish_read(tty);
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
    tty_finish_read(tty);
    return to_read;
}

ssize_t tty_consume_input_iter(iovec_iter *iter, size_t buflen, struct tty *tty)
{
    bool consuming_from_eof = tty->input_buf[buflen - 1] == TTY_CC(tty, VEOF);

    if (consuming_from_eof)
        buflen--;

    ssize_t copied = copy_to_iter(iter, tty->input_buf, buflen);
    if (copied < 0)
    {
        return -EFAULT;
    }

    size_t to_remove_from_buf = copied;
    if (consuming_from_eof)
    {
        /* Discord the EOF character too */
        to_remove_from_buf++;
    }

    tty->input_buf_pos -= to_remove_from_buf;
    memcpy(tty->input_buf, tty->input_buf + to_remove_from_buf,
           sizeof(tty->input_buf) - to_remove_from_buf);
    tty_finish_read(tty);
    return copied;
}

size_t ttydevfs_read(size_t offset, size_t count, void *buffer, struct file *this_)
{
    struct tty *tty = (struct tty *) this_->f_ino->i_helper;

    int st = tty_wait_for_line(this_->f_flags, tty);

    if (st != 0)
        return (size_t) st;

    size_t len = __tty_has_input_available(tty);
    size_t read = tty_consume_input(buffer, count, len, tty);

    mutex_unlock(&tty->input_lock);

    return read;
}

ssize_t ttydevfs_read_iter(file *filp, size_t offset, iovec_iter *iter, unsigned int flags)
{
    (void) offset;
    (void) flags;
    struct tty *tty = (struct tty *) filp->f_ino->i_helper;

    int st = tty_wait_for_line(filp->f_flags, tty);

    if (st != 0)
    {
        return (size_t) st;
    }

    size_t len = __tty_has_input_available(tty);
    size_t read = tty_consume_input_iter(iter, len, tty);

    mutex_unlock(&tty->input_lock);

    return read;
}

void tty_flush_input(struct tty *tty)
{
    mutex_lock(&tty->input_lock);

    tty->input_buf_pos = 0;

    mutex_unlock(&tty->input_lock);
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
            scoped_lock g{proc->sig->pgrp_lock};
            proc->sig->ctty = nullptr;
        },
        PIDTYPE_SID);
    put_pid(tty->session);
    put_pid(tty->pgrp);
    tty->session = nullptr;
    tty->pgrp = NULL;
}

void tty_set_ctty_unlocked(tty *tty)
{
    /* tasklist_lock held */
    auto current = get_current_process();

    if (tty->session)
        put_pid(tty->session);
    if (tty->pgrp)
        put_pid(tty->pgrp);
    tty->session = task_session_locked(current);
    tty->pgrp = task_pgrp_locked(current);
    get_pid(tty->pgrp);
    get_pid(tty->session);
    current->sig->ctty = tty;
}

unsigned int do_tty_csctty(tty *tty, int force)
{
    int err = -EPERM;
    scoped_mutex g2{tty->lock};
    auto current = get_current_process();

    if (force != 0 && force != 1)
        return -EINVAL;

    read_lock(&tasklist_lock);

    // The process must be a session leader
    if (!current->is_session_leader_unlocked())
        goto out;

    // ...and not have a controlling terminal
    if (current->sig->ctty)
        goto out;

    if (tty->session)
    {
        if (force == 1 && is_root_user())
        {
            // If the terminal is already the ctty for a session, but we're forcing it and have
            // proper privs clear the tty from every process belonging to the session and steal it
            tty_clear_session(tty);
        }
        else
            goto out;
    }

    tty_set_ctty_unlocked(tty);
    err = 0;

out:
    read_unlock(&tasklist_lock);
    return err;
}

dev_t ctty_dev = 0;

void process_clear_tty(tty *tty)
{
    // Get the tty's foreground pgrp and send SIGHUP + SIGCONT
    pid_kill_pgrp(tty->pgrp, SIGHUP, 0, NULL);
    pid_kill_pgrp(tty->pgrp, SIGCONT, 0, NULL);

    // Clear the associated session, foreground pgrp data and the controlling ttys of the whole
    // session.
    tty_clear_session(tty);
}

unsigned int do_tty_cnotty(tty *tty)
{
    scoped_mutex g{tty->lock};
    int err = -ENOTTY;
    auto current = get_current_process();

    // Nothing to do if we're not the ctty of the current process
    if (tty != current->sig->ctty)
        return err;

    read_lock(&tasklist_lock);

    // If we're not the session leader, we just clear our own ctty
    // and return. Easy.
    if (!current->is_session_leader_unlocked())
        current->sig->ctty = NULL;
    else
        process_clear_tty(tty);

    err = 0;
    read_unlock(&tasklist_lock);
    return err;
}

static unsigned int do_tiocspgrp(struct tty *tty, pid_t pid)
{
    int err;
    struct pid *pgrp, *old;
    struct process *current = get_current_process();
    if (current->sig->ctty != tty || tty->session != current->sig->session)
        return -ENOTTY;

    rcu_read_lock();
    pgrp = pid_lookup(pid);
    err = -ESRCH;
    if (!pgrp || !pid_is(pgrp, PIDTYPE_PGRP))
        goto err;
    if (!get_pid_not_zero(pgrp))
        goto err;

    err = -EPERM;
    if (!pgrp_is_in_session(pgrp, tty->session))
    {
        put_pid(pgrp);
        goto err;
    }

    old = tty->pgrp;
    tty->pgrp = pgrp;
    put_pid(old);
    rcu_read_unlock();
    return 0;
err:
    rcu_read_unlock();
    return err;
}

unsigned int tty_ioctl(int request, void *argp, struct file *dev)
{
    struct tty *slave_tty;
    struct tty *tty = (struct tty *) dev->f_ino->i_helper;

    slave_tty = tty;
    if (tty->flags & TTY_FLAG_MASTER_PTY)
        slave_tty = (struct tty *) tty->priv;

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
            rw_lock_read(&slave_tty->termio_lock);

            struct termios *term = (termios *) argp;
            if (copy_to_user(term, &slave_tty->term_io, sizeof(struct termios)) < 0)
                ret = -EFAULT;

            rw_unlock_read(&slave_tty->termio_lock);

            return ret;
        }
        case TCSETS:
        case TCSETSW:
        case TCSETSF: {
            return tty_tcsets(request, slave_tty, (termios *) argp);
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
            if (slave_tty->ops->ioctl)
                return slave_tty->ops->ioctl(request, argp, slave_tty);
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
            pid_t pid;
            if (copy_from_user(&pid, argp, sizeof(int)))
                return -EFAULT;
            return do_tiocspgrp(tty, pid);
        }

        case TIOCGPGRP: {
            scoped_mutex g{tty->lock};
            if (get_current_process()->sig->ctty != tty)
                return -ENOTTY;
            CHECK(tty->pgrp);
            pid_t pid = pid_nr(tty->pgrp);
            return copy_to_user(argp, &pid, sizeof(pid_t));
        }

        case TIOCGSID: {
            scoped_mutex g{tty->lock};
            auto session = tty->session;
            if (!session)
                return -ENOTTY;
            auto sid = pid_nr(session);

            return copy_to_user(argp, &sid, sizeof(pid_t));
        }

        default:
            if (tty->ops->ioctl)
                return tty->ops->ioctl(request, argp, tty);
            return -EINVAL;
    }
    return -EINVAL;
}

short tty_poll(void *poll_file, short events, struct file *f)
{
    struct tty *tty = (struct tty *) f->f_ino->i_helper;

    short revents = 0;

    if (events & POLLOUT)
    {
        mutex_lock(&tty->lock);
        if (tty_write_room(tty))
            revents |= POLLOUT;
        else
            poll_wait_helper(poll_file, &tty->write_queue);
        mutex_unlock(&tty->lock);
    }

    if (events & POLLIN)
    {
        /* We lock termio for reading here because tty_has_input_available will touch the termio */
        rw_lock_read(&tty->termio_lock);

        mutex_lock(&tty->input_lock);

        if (__tty_has_input_available(tty))
            revents |= POLLIN;
        else
            poll_wait_helper(poll_file, &tty->read_queue);

        mutex_unlock(&tty->input_lock);

        rw_unlock_read(&tty->termio_lock);
    }

    return revents & events;
}

int ttyopen_try_to_set_ctty(tty *tty)
{
    auto current = get_current_process();

    read_lock(&tasklist_lock);
    if (current->is_session_leader_unlocked() && !current->sig->ctty && !tty->session)
    {
        // If we're a session leader without a tty, and this tty has no session
        // set our ctty to this one
        tty_set_ctty_unlocked(tty);
    }

    read_unlock(&tasklist_lock);
    return 0;
}

int ttydev_on_open_unlocked(struct file *filp)
{
    struct tty *tty = (struct tty *) filp->f_ino->i_helper;

    bool noctty = filp->f_flags & O_NOCTTY;

    if (!noctty)
        return ttyopen_try_to_set_ctty(tty);
    return 0;
}

int ttydev_open(file *f)
{
    struct tty *tty = (struct tty *) f->f_ino->i_helper;
    scoped_mutex g{tty->lock};
    return ttydev_on_open_unlocked(f);
}

const struct file_ops tty_fops = {.read = ttydevfs_read,
                                  .write = ttydevfs_write,
                                  .ioctl = tty_ioctl,
                                  .on_open = ttydev_open,
                                  .poll = tty_poll,
                                  .read_iter = ttydevfs_read_iter};

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
    scoped_lock g{current_process->sig->pgrp_lock};

    if (!current_process->sig->ctty)
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
    new_inode->i_helper = current_process->sig->ctty;
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

static const struct tty_ops console_ops = {
    .write = kernel_console_write,
};

static void kernel_console_ctor(struct tty *tty)
{
    // TODO: Determine the best console we have
    tty->ops = &console_ops;
}
/**
 * @brief Create a kernel console tty
 *
 */
void console_init()
{
    tty_init(nullptr, kernel_console_ctor, 0);
}

static chardev *pty_master;

/**
 * @brief Create the pty master device
 *
 * @param ops PTY master ops
 */
void tty_init_pty_dev(const struct file_ops *ops)
{
    /* We need C++ for this, this is annoying :/ */
    pty_master = dev_register_chardevs(0, 1, 0, ops, "ptmx").unwrap();
    pty_master->show(0666);
}

/**
 * @brief Register a pty slave
 *
 * @param tty PTY to register
 * @param slave_ops PTY slave ops
 * @return 0 on success, negative error codes
 */
int pty_register_slave(struct tty *tty, const struct file_ops *slave_ops)
{
    char namebuf[20];
    sprintf(namebuf, "%lu", tty->tty_num);
    return dev_register_chardevs(0, 1, 0, slave_ops, "pts")
        .then([namebuf, tty](chardev *dev) -> expected<chardev *, int> {
            if (int st = dev->show_with_name(namebuf, "pts/", 0620); st < 0)
                return unexpected<int>{st};
            dev->private_ = tty;
            return dev;
        })
        .error_or(0);
}

unsigned int tty_write_room(struct tty *tty)
{
    if (tty->ops->write_room)
        return tty->ops->write_room(tty);
    return 4096;
}
