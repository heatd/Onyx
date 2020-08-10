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
	tty->tty_num = idm_get_id(tty_ids);
	tty->term_io.c_lflag = ICANON | ECHO;
	init_wait_queue_head(&tty->read_queue);
	/** Use the ctor to init the tty with write and read functions */
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

	tty->write((void *) data, size, tty);

	mutex_unlock(&tty->lock);
}

#define TTY_PRINT_IF_ECHO(c, l, t) if(t->term_io.c_lflag & ECHO) tty_write(c, l, t)

void tty_received_character(struct tty *tty, char c)
{
	if(c == '\b')
	{
		if(tty->keyboard_pos <= 0)
		{
			tty->keyboard_pos = 0;
			goto out;
		}

		TTY_PRINT_IF_ECHO("\b \b", 3, tty);

		tty->keyboard_buffer[tty->keyboard_pos] = 0;
		tty->keyboard_pos--;
		goto out;
	}

	tty->keyboard_buffer[tty->keyboard_pos++] = c;
	TTY_PRINT_IF_ECHO(&c, 1, tty);

out:
	if(!(tty->term_io.c_lflag & ICANON))
	{
		tty->line_ready = true;
		wait_queue_wake_all(&tty->read_queue);
	}
	else if(c == '\n')
	{
		tty->line_ready = true;
		wait_queue_wake_all(&tty->read_queue);
	}
}

char *tty_wait_for_line(unsigned int flags, struct tty *tty)
{
	if(flags & O_NONBLOCK && !tty->line_ready)
		return tty->keyboard_buffer;

	wait_for_event(&tty->read_queue, tty->line_ready);

	tty->line_ready = false;
	return tty->keyboard_buffer;
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

size_t ttydevfs_write(size_t offset, size_t sizeofwrite, void* buffer, struct file *this)
{
	struct tty *tty = this->f_ino->i_helper;
	
	tty_write(buffer, sizeofwrite, tty);
	return sizeofwrite;
}

size_t strnewlinelen(char *str)
{
	size_t len = 0;
	for(; *str != '\n'; ++str)
		++len;
	return len+1;
}

size_t ttydevfs_read(size_t offset, size_t count, void *buffer, struct file *this)
{
	struct tty *tty = this->f_ino->i_helper;

	char *kb_buf = tty_wait_for_line(this->f_flags, tty);
	size_t len = tty->term_io.c_lflag & ICANON ? strnewlinelen(kb_buf) : strlen(kb_buf);
	size_t read = count < len ? count : len;
	memcpy(buffer, kb_buf, read);
	tty->keyboard_pos -= read;
	memcpy(kb_buf, kb_buf + read, 2048 - read);

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
			if(copy_to_user(arg, (const void *) &tty->keyboard_pos, sizeof(int)) < 0)
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
	
	if(events & POLLIN)
		poll_wait_helper(poll_file, &tty->read_queue);

	short revents = POLLOUT;
	if(tty->line_ready)
		revents |= POLLIN;
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
