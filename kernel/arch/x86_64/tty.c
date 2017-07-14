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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>

#include <bits/ioctl.h>

#include <kernel/task_switching.h>
#include <kernel/portio.h>
#include <kernel/tty.h>
#include <kernel/video.h>
#include <kernel/mutex.h>

#include <kernel/panic.h>
#include <kernel/dev.h>

static struct termios term_io = {.c_lflag = ICANON | ECHO};
static struct video_device *main_device = NULL;
unsigned int max_row = 0;
static const unsigned int max_row_fallback = 1024/16;
unsigned int max_column = 0;
static const unsigned int max_column_fallback = 768/8;
size_t terminal_row = 0;
size_t terminal_column = 0;
uint32_t last_x = 0;
uint32_t last_y = 0;
int terminal_color = 0;
int currentPty = 0;
void* fbs[5] ={(void*) 0xDEADDEAD/*Vid mem*/,NULL};
void tty_init(void)
{
	terminal_row = 1;
	terminal_column = 0;
	terminal_color = 0xC0C0C0;
	main_device = video_get_main_adapter();
	struct video_mode *vid = video_get_videomode(main_device);
	if( vid->width == 0 ) {
		max_row = max_row_fallback;
		max_column = max_column_fallback;
	} else {
		max_row = vid->height / 16;
		max_column = vid->width / 8;
	}
}

void tty_set_color(int color)
{
	terminal_color = color;
}
void tty_draw_cursor(int x, int y, int fgcolor, int bgcolor, void *fb)
{
retry:;
	int err = video_draw_cursor(x, y, fgcolor, bgcolor, fb, main_device);
	if(errno == ENODEV && err < 0)
	{
		main_device = video_get_main_adapter();
		goto retry;
	}
}
void tty_draw_char(unsigned char c, int x, int y, int fgcolor, int bgcolor, void* fb)
{
retry:;
	int err = video_draw_char(c, x, y, fgcolor, bgcolor, fb, main_device);
	if(errno == ENODEV && err < 0)
	{
		main_device = video_get_main_adapter();
		goto retry;
	}
}
void __tty_scroll(void *fb)
{
retry:;
	int err = video_scroll(fb, main_device);
	if(errno == ENODEV && err < 0)
	{
		main_device = video_get_main_adapter();
		goto retry;
	}
}
void *tty_get_fb()
{
retry:;
	void *err = video_get_fb(main_device);
	if(errno == ENODEV && err == 0)
	{
		main_device = video_get_main_adapter();
		goto retry;
	}
	return err;
}
void tty_put_entry_at(char c, uint32_t color, size_t column, size_t row)
{
	
	int y = row * 16;
	int x = column * 8;
	last_x = x + 9;
	last_y = y;
	tty_draw_char(c, x, y, color, 0, fbs[currentPty]);
	tty_draw_cursor(x + 9, y, 0, 0xC0C0C0, fbs[currentPty]);
}
void tty_putchar(char c)
{
	if(c == '\n')
	{
		newline:
		terminal_column = 0;
		terminal_row++;
		if(terminal_row >= max_row)
		{
			tty_draw_cursor(last_x, last_y, 0, 0, fbs[currentPty]);
			tty_scroll();
		}
		tty_draw_cursor(last_x, last_y, 0, 0, fbs[currentPty]);
		tty_draw_cursor(terminal_column * 8, terminal_row * 16, 0,
			  0xC0C0C0, fbs[currentPty]);
		last_x = terminal_column * 8;
		last_y = terminal_row * 16;
		return;
	}
	if (c == '\t')
	{
		for(int i = 0; i < 8; i++)
		{
			tty_put_entry_at(' ', terminal_color, terminal_column, terminal_row);
			terminal_column++;
		}
		return;
	}
	if(c == '\b')
	{
		size_t column = 0, row = terminal_row;
		if(terminal_column)
			column = terminal_column-1;
		else
		{
			row--;
			column = max_column;
		}
		tty_draw_cursor(terminal_column * 8, terminal_row * 16, 0, 0, fbs[currentPty]);
		tty_draw_cursor(column * 8, row * 16, 0, 0, fbs[currentPty]);
		tty_draw_cursor(column * 8, row * 16, 0, 0xC0C0C0, fbs[currentPty]);
		int y = row * 16;
		int x = column * 8;
		last_x = x;
		last_y = y;
		terminal_column = column;
		terminal_row = row;
		return;
	}
	if( terminal_column == max_column ) {
		/* If we reach the line limit, fake a newline */
		goto newline;
	}
	tty_put_entry_at(c, terminal_color, terminal_column,
			    terminal_row);
	terminal_column++;
}
static mutex_t ttylock = MUTEX_INITIALIZER;
void tty_write(const char *data, size_t size)
{
	mutex_lock(&ttylock);
	for (size_t i = 0; i < size; i++)
	{
		// Parse ANSI terminal escape codes
		if(!memcmp(&data[i], ANSI_COLOR_RED, strlen(ANSI_COLOR_RED)))
		{
			tty_set_color(TTY_DEFAULT_RED);
			i += strlen(ANSI_COLOR_RED);
			if(i >= size) break;
		}
		if(!memcmp(&data[i], ANSI_COLOR_GREEN, strlen(ANSI_COLOR_GREEN)))
		{
			tty_set_color(TTY_DEFAULT_GREEN);
			i += strlen(ANSI_COLOR_GREEN);
			if(i >= size) break;			
		}
		if(!memcmp(&data[i], ANSI_COLOR_YELLOW, strlen(ANSI_COLOR_YELLOW)))
		{
			tty_set_color(TTY_DEFAULT_YELLOW);
			i += strlen(ANSI_COLOR_YELLOW);
			if(i >= size) break;
		}
		if(!memcmp(&data[i], ANSI_COLOR_BLUE, strlen(ANSI_COLOR_BLUE)))
		{
			tty_set_color(TTY_DEFAULT_BLUE);
			i += strlen(ANSI_COLOR_BLUE);
			if(i >= size) break;
		}
		if(!memcmp(&data[i], ANSI_COLOR_MAGENTA, strlen(ANSI_COLOR_MAGENTA)))
		{
			tty_set_color(TTY_DEFAULT_MAGENTA);
			i += strlen(ANSI_COLOR_MAGENTA);
			if(i >= size) break;
		}
		if(!memcmp(&data[i], ANSI_COLOR_CYAN, strlen(ANSI_COLOR_CYAN)))
		{
			tty_set_color(TTY_DEFAULT_CYAN);
			i += strlen(ANSI_COLOR_CYAN);
			if(i >= size) break;
		}
		if(!memcmp(&data[i], ANSI_COLOR_RESET, strlen(ANSI_COLOR_RESET)))
		{
			tty_set_color(TTY_RESET_COLOR);
			i += strlen(ANSI_COLOR_RESET);
			if(i >= size) break;
		}
		tty_putchar(data[i]);
	}
	if(currentPty != 0)
		tty_swap_framebuffers();
	mutex_unlock(&ttylock);
}
#define TTY_PRINT_IF_ECHO(c, l) if(term_io.c_lflag & ECHO) tty_write(c, l)
char keyboard_buffer[2048];
volatile int tty_keyboard_pos = 0;
volatile _Bool got_line_ready = 0;
void tty_recieved_character(char c)
{
	if(!(term_io.c_lflag & ICANON))
		got_line_ready = 1;
	if(c == '\n')
	{
		got_line_ready = 1;
	}
	if(c == '\b')
	{
		if(tty_keyboard_pos <= 0)
		{
			tty_keyboard_pos = 0;
			return;
		}
		TTY_PRINT_IF_ECHO(&c, 1);
		keyboard_buffer[tty_keyboard_pos] = 0;
		tty_keyboard_pos--;
		return;
	}
	keyboard_buffer[tty_keyboard_pos++] = c;
	TTY_PRINT_IF_ECHO(&c, 1);
}
char *tty_wait_for_line(int flags)
{
	if(flags & O_NONBLOCK && !got_line_ready)
		return keyboard_buffer;
	while(!got_line_ready)
	{
		sched_yield();
	}
	got_line_ready = 0;
	return keyboard_buffer;
}
void tty_swap_framebuffers()
{
	memcpy(tty_get_fb(), fbs[currentPty], 0x400000);
}
void tty_write_string(const char *data)
{
	tty_write(data, strlen(data));
}
void tty_scroll()
{
	__tty_scroll(fbs[currentPty]);
	terminal_row--;
	terminal_column = 0;
	tty_swap_framebuffers();
}
int tty_create_pty_and_switch(void* address)
{
	currentPty++;
	/* Save the fb address */
	fbs[currentPty] = address;
	memset(tty_get_fb(), 0, 0x400000);
	terminal_row = 1;
	terminal_column = 0;
	tty_draw_char('\0', terminal_column * 9, terminal_row * 16, 0,
		  0xC0C0C0, fbs[currentPty]);
	last_x = terminal_column * 9;
	last_y = terminal_row * 16;
	tty_swap_framebuffers();
	return 0;
}
size_t ttydevfs_write(size_t offset, size_t sizeofwrite, void* buffer, struct vfsnode* this)
{
	tty_write(buffer, sizeofwrite);
	return sizeofwrite;
}
size_t strnewlinelen(char *str)
{
	size_t len = 0;
	for(; *str != '\n'; ++str)
		++len;
	return len+1;
}
size_t ttydevfs_read(int flags, size_t offset, size_t count, void *buffer, vfsnode_t *this)
{
	char *kb_buf = tty_wait_for_line(flags);
	size_t len = term_io.c_lflag & ICANON ? strnewlinelen(kb_buf) : strlen(kb_buf);
	size_t read = count < len ? count : len;
	memcpy(buffer, kb_buf, read);
	tty_keyboard_pos -= read;
	memcpy(kb_buf, kb_buf + read, 2048 - read);
	return read;
}

unsigned int tty_ioctl(int request, void *argp, vfsnode_t *dev)
{
	switch(request)
	{
		case TCGETS:
		{
			struct termios *term = argp;
			if(vmm_check_pointer(term, sizeof(struct termios)) < 0)
				return -EFAULT;
			memcpy(term, &term_io, sizeof(struct termios));
			return 0;
		}
		case TCSETS:
		{
			struct termios *term = argp;
			if(vmm_check_pointer(term, sizeof(struct termios)) < 0)
				return -EFAULT;
			memcpy(&term_io, term, sizeof(struct termios));
			return 0;
		}
		case TCSETSW:
		{
			struct termios *term = argp;
			if(vmm_check_pointer(term, sizeof(struct termios)) < 0)
				return -EFAULT;
			memcpy(&term_io, term, sizeof(struct termios));
			return 0;
		}
		case TCSETSF:
		{
			struct termios *term = argp;
			if(vmm_check_pointer(term, sizeof(struct termios)) < 0)
				return -EFAULT;
			memcpy(&term_io, term, sizeof(struct termios));
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
			struct winsize *win = argp;
			if(vmm_check_pointer(win, sizeof(struct winsize)) < 0)
				return -EFAULT;
			win->ws_row = max_row;
			win->ws_col = max_column;
			struct video_mode *vid = video_get_videomode(main_device);
			win->ws_xpixel = vid->width;
			win->ws_ypixel = vid->height;
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
			if(vmm_check_pointer(arg, sizeof(int)) < 0)
				return -EFAULT;
			*arg = tty_keyboard_pos;
			return 0;
		}
		default:	
			return -EINVAL;
	}
	return -EINVAL;
}
void tty_create_dev()
{
	vfsnode_t *ttydev = creat_vfs(slashdev, "tty", 0666);
	if(!ttydev)
		panic("Could not allocate /dev/tty!\n");

	struct minor_device *minor = dev_register(0, 0);
	if(!minor)
		panic("Could not allocate a device ID!\n");
	
	minor->fops = malloc(sizeof(struct file_ops));
	if(!minor->fops)
		panic("Could not allocate a file operation table!\n");
	
	memset(minor->fops, 0, sizeof(struct file_ops));

	ttydev->dev = minor->majorminor;
	minor->fops->write = ttydevfs_write;
	minor->fops->read = ttydevfs_read;
	minor->fops->ioctl = tty_ioctl;
	ttydev->type = VFS_TYPE_CHAR_DEVICE;
}
