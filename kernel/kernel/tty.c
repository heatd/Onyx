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
#include <onyx/portio.h>
#include <onyx/tty.h>
#include <onyx/framebuffer.h>
#include <onyx/mutex.h>
#include <onyx/id.h>
#include <onyx/panic.h>
#include <onyx/dev.h>
#include <onyx/condvar.h>

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
	tty->tty_num = idm_get_id(tty_ids);
	tty->term_io.c_lflag = ICANON | ECHO;
	/** Use the ctor to init the tty with write and read functions */
	ctor(tty);

	tty_add(tty);

	printf("tty: Added tty%lu\n", tty->tty_num);
}

void tty_write(const char *data, size_t size, struct tty *tty)
{
	mutex_lock(&tty->lock);

	tty->write((void *) data, size, tty);

	mutex_unlock(&tty->lock);
}

#define TTY_PRINT_IF_ECHO(c, l, t) if(t->term_io.c_lflag & ECHO) tty_write(c, l, t)

void tty_recieved_character(struct tty *tty, char c)
{
	
	if(!(tty->term_io.c_lflag & ICANON))
	{
		tty->line_ready = true;
		condvar_broadcast(&tty->read_cond);
	}
	else if(c == '\n')
	{
		tty->line_ready = true;
		condvar_broadcast(&tty->read_cond);
	}

	if(c == '\b')
	{
		if(tty->keyboard_pos <= 0)
		{
			tty->keyboard_pos = 0;
			return;
		}
		TTY_PRINT_IF_ECHO(&c, 1, tty);
		tty->keyboard_buffer[tty->keyboard_pos] = 0;
		tty->keyboard_pos--;
		return;
	}

	tty->keyboard_buffer[tty->keyboard_pos++] = c;
	TTY_PRINT_IF_ECHO(&c, 1, tty);
}

char *tty_wait_for_line(int flags, struct tty *tty)
{
	if(flags & O_NONBLOCK && !tty->line_ready)
		return tty->keyboard_buffer;

	while(!tty->line_ready)
	{
		mutex_lock(&tty->read_mtx);
		condvar_wait(&tty->read_cond, &tty->read_mtx);
	}

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

size_t ttydevfs_write(size_t offset, size_t sizeofwrite, void* buffer, struct inode* this)
{
	struct tty *tty = this->i_helper;
	
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

size_t ttydevfs_read(int flags, size_t offset, size_t count, void *buffer, struct inode *this)
{
	struct tty *tty = this->i_helper;

	char *kb_buf = tty_wait_for_line(flags, tty);
	size_t len = tty->term_io.c_lflag & ICANON ? strnewlinelen(kb_buf) : strlen(kb_buf);
	size_t read = count < len ? count : len;
	memcpy(buffer, kb_buf, read);
	tty->keyboard_pos -= read;
	memcpy(kb_buf, kb_buf + read, 2048 - read);

	mutex_unlock(&tty->read_mtx);

	return read;
}

unsigned int tty_ioctl(int request, void *argp, struct inode *dev)
{
	struct tty *tty = dev->i_helper;

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
			tty->ioctl(request, argp, tty);
			return 0;
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
		default:	
			return -EINVAL;
	}
	return -EINVAL;
}

void tty_create_dev(void)
{
	struct dev *minor = dev_register(0, 0, "tty");
	if(!minor)
		panic("Could not allocate a device ID!\n");	

	minor->fops.write = ttydevfs_write;
	minor->fops.read = ttydevfs_read;
	minor->fops.ioctl = tty_ioctl;
	minor->priv = main_tty;
	device_show(minor, DEVICE_NO_PATH);
}
