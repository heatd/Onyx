/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>

#include <bits/ioctl.h>

#include <onyx/task_switching.h>
#include <onyx/port_io.h>
#include <onyx/tty.h>
#include <onyx/framebuffer.h>
#include <onyx/mutex.h>
#include <onyx/id.h>
#include <onyx/panic.h>
#include <onyx/dev.h>
#include <onyx/condvar.h>
#include <onyx/poll.h>

void vterm_release_video(void *vterm);
void vterm_get_video(void *vt);

struct tty *main_tty = NULL;

struct ids *tty_ids;

int tty_add(struct tty *tty)
{
	struct tty **pp = &main_tty;

	while(*pp)
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

	/* ICRNL - translate CR into NL ; IXON - Enable XON/XOFF flow control on output ; IUTF8 - Input is UTF8 */
	tty->term_io.c_iflag = ICRNL | IXON | IUTF8;

	/* OPOST - Impl. defined output processing ; ONLCR - Map NL to CRNL ; All other flags are delay masks of 0 */
	tty->term_io.c_oflag = OPOST | ONLCR | NL0 | CR0 | TAB0 | BS0 | VT0 | FF0;
	/* ISIG - Generate corresponding signals when specific characters are received.
	 * ICANON - Enable canonical mode.
	 * IEXTEN - Enable implementation defined input processing.
	 * ECHO - Echo input characters.
	 * ECHOE - if ICANON, the ERASE character erases the preceeding input character,
	 *         and WERASE erases the preceeding word.
	 * ECHOK - if ICANON, the KILL character erases the current line.
	 * ECHOCTL - if ECHO is also set, special characters other than TAB, NL, START, STOP are echo'd as ^X, where
	 *           X is the character with ASCII code 0x40 greater than the special character.
	 * ECHOKE - if ICANON, KILL is echoed by erasing each character on the line.
	 *
	 */
	tty->term_io.c_lflag = ISIG | ICANON | IEXTEN | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE;
	tty->term_io.c_cc[VINTR] = 003;
	tty->term_io.c_cc[VQUIT] = 034;
	tty->term_io.c_cc[VERASE] = '\b';
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

	/* TODO: Properly implement this */
	tty->term_io.c_cflag = CS8 | B38400 | CREAD | HUPCL;
	tty->term_io.__c_ispeed = tty->term_io.__c_ospeed = 38400;

	tty->term_io.c_line = N_TTY;
}

extern struct tty_line_disc ntty_disc;

void tty_init(void *priv, void (*ctor)(struct tty *tty))
{
	if(!tty_ids)
	{
		tty_ids = idm_add("tty", 0, UINTMAX_MAX);

		assert(tty_ids != NULL);
	}

	struct tty *tty = zalloc(sizeof(*tty));

	assert(tty != NULL);

	tty->priv = priv;
	mutex_init(&tty->lock);
	spinlock_init(&tty->input_lock);

	tty->tty_num = idm_get_id(tty_ids);

	init_default_tty_termios(tty);

	tty->ldisc = &ntty_disc;

	init_wait_queue_head(&tty->read_queue);

	/** Use the ctor to init the tty */
	ctor(tty);

	tty_add(tty);

	printf("tty: Added tty%lu\n", tty->tty_num);
}

extern struct serial_port com1;
void serial_write(const char *s, size_t size, struct serial_port *port);

void cpu_kill_other_cpus(void);

void tty_write(const char *data, size_t size, struct tty *tty)
{
	if(tty->lock.owner == get_current_thread() && get_current_thread() != NULL)
	{
		tty->lock.counter = 0;
		tty->lock.owner = NULL;
		const char *msg = "recursive tty lock";
		serial_write(msg, strlen(msg), &com1);
		cpu_kill_other_cpus();
		halt();
	}

	mutex_lock(&tty->lock);

	tty->ldisc->ops->write_out(data, size, tty);

	mutex_unlock(&tty->lock);
}

void tty_received_character(struct tty *tty, char c)
{
	tty->ldisc->ops->receive_input(c, tty);
}

ssize_t __tty_has_input_available(struct tty *tty)
{
	bool is_canonical = TTY_LFLAG(tty, ICANON);

	for(size_t i = 0; i < tty->input_buf_pos; i++)
	{
		if(is_canonical && tty->input_buf[i] == '\n')
			return i + 1;
		
		if(tty->input_buf[i] == TTY_CC(tty, VEOF))
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

	if(ret == 0 && flags & O_NONBLOCK)
		ret = -EAGAIN;

	return ret;
}

ssize_t tty_wait_for_line(unsigned int flags, struct tty *tty)
{
	spin_lock(&tty->input_lock);

	int res = -EWOULDBLOCK;

	if(flags & O_NONBLOCK && !tty_has_input_available(flags, tty))
		goto out_error;

	res = wait_for_event_locked_interruptible(&tty->read_queue, __tty_has_input_available(tty) != 0, &tty->input_lock);

	if(res < 0)
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
	if(!main_tty)
		return;
	tty_write(data, size, main_tty);
}

void tty_write_string_kernel(const char *data)
{
	if(!main_tty)
		return;
	tty_write_string(data, main_tty);
}

size_t ttydevfs_write(size_t offset, size_t len, void *ubuffer, struct file *f)
{
	struct tty *tty = f->f_ino->i_helper;

	char *buffer = malloc(len);
	if(!buffer)
		return (size_t) -ENOMEM;
	
	if(copy_from_user(buffer, ubuffer, len) < 0)
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
	for(; *str != '\n' && len != 0; ++str, _len--)
		++len;
	return len + 1;
}

ssize_t tty_consume_input(void *ubuf, size_t len, size_t buflen, struct tty *tty)
{
	bool consuming_from_eof = tty->input_buf[buflen - 1] == TTY_CC(tty, VEOF);

	if(consuming_from_eof)
		buflen--;

	size_t to_read = min(len, buflen);

	if(copy_to_user(ubuf, tty->input_buf, to_read) < 0)
	{
		return -EFAULT;
	}

	size_t to_remove_from_buf = to_read;

	if(consuming_from_eof)
	{
		/* Discard the EOF character too */
		to_remove_from_buf++;
	}

	tty->input_buf_pos -= to_remove_from_buf;
	memcpy(tty->input_buf, tty->input_buf + to_remove_from_buf, sizeof(tty->input_buf) - to_remove_from_buf);

	return to_read;
}

size_t ttydevfs_read(size_t offset, size_t count, void *buffer, struct file *this)
{
	struct tty *tty = this->f_ino->i_helper;

	int st = tty_wait_for_line(this->f_flags, tty);

	if(st < 0)
		return (size_t) st;

	size_t len = __tty_has_input_available(tty);
	size_t read = tty_consume_input(buffer, count, len, tty);

	spin_unlock(&tty->input_lock);

	return read;
}

unsigned int tty_ioctl(int request, void *argp, struct file *dev)
{
	struct tty *tty = dev->f_ino->i_helper;

	switch(request)
	{
		case TCGETS:
		{
			struct termios *term = argp;
			if(copy_to_user(term, &tty->term_io, sizeof(struct termios)) < 0)
				return -EFAULT;
			return 0;
		}
		case TCSETS:
		{
			struct termios *term = argp;
			if(copy_from_user(&tty->term_io, term, sizeof(struct termios)) < 0)
				return -EFAULT;
			return 0;
		}
		case TCSETSW:
		{
			struct termios *term = argp;
			if(copy_from_user(&tty->term_io, term, sizeof(struct termios)) < 0)
				return -EFAULT;
			return 0;
		}
		case TCSETSF:
		{
			struct termios *term = argp;
			if(copy_from_user(&tty->term_io, term, sizeof(struct termios)) < 0)
				return -EFAULT;
			return 0;
		}
		case TCGETA:
		case TCSETA:
		case TCSETAW:
		case TCSETAF:
			return 0;
		case TIOCGLCKTRMIOS:
		case TIOCSLCKTRMIOS:
			return 0;
		case TIOCGWINSZ:
		{
			return tty->ioctl(request, argp, tty);
		}
		case TIOCSWINSZ:
		{
			/* We don't support this yet */
			return 0;
		}
		case TCSBRK:
		case TCSBRKP:
		case TIOCSBRK:
		case TIOCCBRK:
			return 0;
		case TCXONC:
		{
			/* TODO */
			return 0;
		}
		case TIOCINQ:
		{
			int *arg = argp;
			if(copy_to_user(arg, (const void *) &tty->input_buf_pos, sizeof(int)) < 0)
				return -EFAULT;
			return 0;
		}
		case TIOONYXCTL:
		{
			int arg = (int) (unsigned long) argp;

			switch(arg)
			{
				case TIO_ONYX_GET_OWNERSHIP_OF_TTY:
					/* Disable canon and echo */
					tty->term_io.c_lflag &= ~(ICANON | ECHO);
					if(tty->is_vterm)
					{
						vterm_release_video(tty->priv);
					}
					return 0;
				case TIO_ONYX_RELEASE_OWNERSHIP_OF_TTY:
				{
					tty->term_io.c_lflag |= ICANON | ECHO;
					if(tty->is_vterm)
					{
						vterm_get_video(tty->priv);
					}
					return 0;
				}
				default:
					return -EINVAL;
			}		
		}

		default:	
			return -EINVAL;
	}
	return -EINVAL;
}

short tty_poll(void *poll_file, short events, struct file *f)
{
	struct tty *tty = f->f_ino->i_helper;

	short revents = POLLOUT;
	
	if(events & POLLIN)
	{
		spin_lock(&tty->input_lock);

		if(__tty_has_input_available(tty))
			revents |= POLLIN;
		else
			poll_wait_helper(poll_file, &tty->read_queue);
		
		spin_unlock(&tty->input_lock);
	}

	return revents & events;
}

void tty_create_dev(void)
{
	struct dev *minor = dev_register(0, 0, "tty");
	if(!minor)
		panic("Could not allocate a device ID!\n");	

	minor->fops.write = ttydevfs_write;
	minor->fops.read = ttydevfs_read;
	minor->fops.ioctl = tty_ioctl;
	minor->fops.poll = tty_poll;

	minor->priv = main_tty;
	device_show(minor, DEVICE_NO_PATH, 0666);
}
