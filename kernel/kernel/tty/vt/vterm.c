/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <ctype.h>

#include <onyx/semaphore.h>
#include <onyx/tty.h>
#include <onyx/framebuffer.h>
#include <onyx/font.h>
#include <onyx/vm.h>
#include <onyx/scheduler.h>
#include <onyx/thread.h>
#include <onyx/init.h>
#include <onyx/serial.h>
#include <onyx/dpc.h>
#include <onyx/utf8.h>

#include <onyx/input/keys.h>
#include <onyx/input/event.h>
#include <onyx/input/state.h>
#include <onyx/input/device.h>

#include <sys/ioctl.h>

#include <sys/types.h>

struct tty;

struct color
{
	uint8_t r;
	uint8_t g;
	uint8_t b;
	uint8_t a;
};

const struct color vterm_default_red = {.r = 0xff};
const struct color vterm_default_green = {.g = 0xff};
const struct color vterm_default_blue = {.b = 0xff};
const struct color vterm_default_yellow = {.r = 0xff, .g = 0xff};
const struct color vterm_default_magenta = {.r = 0xff, .b = 0xff};
const struct color vterm_default_cyan = {.b = 0xff, .g = 0xff};
static struct color default_fg = {.r = 0xaa, .g = 0xaa, .b = 0xaa};
static struct color default_bg = {0};

const struct color color_table[] = 
{
	{.r = 0, .g = 0, .b = 0},          /* Black */
	{.r = 0xff},                       /* Red */
	{.g = 0xff},                       /* Green */
	{.r = 0xff, .g = 0xff},            /* Yellow */
	{.b = 0xff},                       /* Blue */
	{.r = 0xff, .b = 0xff},            /* Magenta */
	{.g = 0xff, .b = 0xff},            /* Cyan */
	{.r = 0xaa, .g = 0xaa, .b = 0xaa}  /* White */
};

#define VTERM_CONSOLE_CELL_DIRTY          (1 << 0)
#define VTERM_CONSOLE_CELL_CONTINUATION   (1 << 1)

struct console_cell
{
	uint32_t codepoint;
	struct color bg;
	struct color fg;
	uint32_t flags;	
};

static inline void vterm_set_dirty(struct console_cell *c)
{
	c->flags |= VTERM_CONSOLE_CELL_DIRTY;
}

static inline void vterm_clear_dirty(struct console_cell *c)
{
	c->flags &= ~VTERM_CONSOLE_CELL_DIRTY;
}

static inline bool vterm_is_dirty(struct console_cell *c)
{
	return c->flags & VTERM_CONSOLE_CELL_DIRTY;
}

#define VTERM_MESSAGE_FLUSH		1
#define VTERM_MESSAGE_FLUSH_ALL		2
#define VTERM_MESSAGE_DIE		3

struct vterm_message
{
	unsigned long message;
	void *ctx;
	struct vterm_message *next;
};

struct vterm
{
	struct mutex vt_lock;
	unsigned int columns;
	unsigned int rows;
	unsigned int cursor_x, cursor_y;
	struct framebuffer *fb;
	struct console_cell *cells;
	struct color fg;
	struct color bg;
	struct thread *blink_thread;
	bool blink_status;	/* true = visible, false = not */
	unsigned int saved_x, saved_y;	/* Used by ANSI_SAVE/RESTORE_CURSOR */
	bool blink_die;
	struct tty *tty;
	bool multithread_enabled;
	struct thread *render_thread;
	struct cond condvar;
	struct mutex condvar_mutex;
	struct vterm_message *msgs;
};

void vterm_append_msg(struct vterm *vterm, struct vterm_message *msg)
{
	mutex_lock(&vterm->condvar_mutex);

	struct vterm_message **pp = &vterm->msgs;

	while(*pp)
	{
		pp = &(*pp)->next;
	}

	*pp = msg;
}

void vterm_send_message(struct vterm *vterm, unsigned long message, void *ctx)
{
	struct vterm_message *msg = zalloc(sizeof(*msg));

	/* TODO: Maybe don't crash here? */
	assert(msg != NULL);

	msg->message = message;
	msg->ctx = ctx;
	msg->next = NULL;

	vterm_append_msg(vterm, msg);

	condvar_signal(&vterm->condvar);

	mutex_unlock(&vterm->condvar_mutex);
}

static inline uint32_t unpack_rgba(struct color color, struct framebuffer *fb)
{
	uint32_t c = 	((color.r << fb->color.red_shift) & fb->color.red_mask) |
			((color.g << fb->color.green_shift) & fb->color.green_mask) |
			((color.b << fb->color.blue_shift) & fb->color.blue_mask);

	return c;
}

static void draw_char(uint32_t c, unsigned int x, unsigned int y,
	struct framebuffer *fb, struct color fg, struct color bg)
{
	struct font *font = get_font_data();

	if(c >= font->chars)
		c = '?';

	volatile char *buffer = (volatile char *) fb->framebuffer;

	buffer += y * fb->pitch + x * (fb->bpp / 8);

	for(int i = 0; i < 16; i++)
	{
		for(int j = 0; j < 8; j++)
		{
			struct color color;
			unsigned char f = font->font_bitmap[c * font->height + i];

			if(f & font->mask[j])
				color = fg;
			else
				color = bg;
			
			uint32_t c = unpack_rgba(color, fb);
			volatile uint32_t *b = (volatile uint32_t *) ((uint32_t *) buffer + j);
			
			/* If the bpp is 32 bits, we can just blit it out */
			if(fb->bpp == 32)
				__asm__ __volatile__("movnti %1, %0" : "=m" (*b) : "r" (c) : "memory");
			else
			{
				volatile unsigned char *buf =
					(volatile unsigned char *)(buffer + j);
				int bytes = fb->bpp / 8;
				for(int i = 0; i < bytes; i++)
				{
					buf[i] = c;
					c >>= 8;
				}
			}
		}

		buffer = (void*) (((char *) buffer) + fb->pitch);
	}
}

void do_vterm_flush_all(struct vterm *vterm)
{
	struct font *f = get_font_data();
	for(unsigned int i = 0; i < vterm->columns; i++)
	{
		for(unsigned int j = 0; j < vterm->rows; j++)
		{
			struct console_cell *cell = &vterm->cells[j * vterm->columns + i];
			draw_char(cell->codepoint, i * f->width, j * f->height,
				vterm->fb, cell->fg, cell->bg);
			vterm_clear_dirty(cell);
		}
	}
}

void vterm_flush_all(struct vterm *vterm)
{
	if(vterm->multithread_enabled)
		vterm_send_message(vterm, VTERM_MESSAGE_FLUSH_ALL, NULL);
	else
		do_vterm_flush_all(vterm);	
}

void vterm_scroll(struct framebuffer *fb, struct vterm *vt)
{
	memcpy(vt->cells, vt->cells + vt->columns, sizeof(struct console_cell)
		* (vt->rows-1) * vt->columns);

	for(unsigned int i = 0; i < vt->columns; i++)
	{
		struct console_cell *c = &vt->cells[(vt->rows-1) * vt->columns + i];
		c->codepoint = ' ';
		c->bg = vt->bg;
		c->fg = vt->fg;
	}

}

void vterm_scroll_down(struct framebuffer *fb, struct vterm *vt)
{
	memmove(vt->cells + vt->columns, vt->cells, sizeof(struct console_cell)
		* (vt->rows-1) * vt->columns);

	for(unsigned int i = 0; i < vt->columns; i++)
	{
		struct console_cell *c = &vt->cells[i];
		c->codepoint = ' ';
		c->bg = vt->bg;
		c->fg = vt->fg;
	}

}
void vterm_set_char(utf32_t c, unsigned int x, unsigned int y, struct color fg,
	struct color bg, struct vterm *vterm)
{
	struct console_cell *cell = &vterm->cells[y * vterm->columns + x];
	cell->codepoint = c;
	cell->fg = fg;
	cell->bg = bg;
	vterm_set_dirty(cell);
}

void vterm_dirty_cell(unsigned int x, unsigned int y, struct vterm *vt)
{
	struct console_cell *cell = &vt->cells[y *
			vt->columns + x];
	vterm_set_dirty(cell);
}

bool vterm_putc(utf32_t c, struct vterm *vt)
{
	if(c == '\0')
		return false;

	if(c == '\t')
	{
		bool did_scroll = false;
		for(int i = 0; i < 8; i++)
		{
			if(vterm_putc(' ', vt) == true)
				did_scroll = true;
		}

		return did_scroll;
	}

	struct framebuffer *fb = vt->fb;

	if(c == '\n')
	{
		vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
		vt->cursor_y++;
	}
	else if(c == '\r')
	{
		vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
		vt->cursor_x = 0;
	}
	else if(c == '\b')
	{
		if(vt->cursor_x == 0)
			return false;

		vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
		vt->cursor_x--;
	}
	else if(c == '\x7f')
	{
		/* Delete char */
		if(vt->cursor_x == 0)
			return false;

		vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
		vt->cursor_x--;
		vterm_set_char(' ', vt->cursor_x, vt->cursor_y, vt->fg, vt->bg, vt);
	}
	else
	{
		vterm_set_char(c, vt->cursor_x, vt->cursor_y, vt->fg, vt->bg, vt);
		vt->cursor_x++;
	}

	if(vt->cursor_x == vt->columns)
	{
		/* Forced newline */
		vt->cursor_x = 0;
		vt->cursor_y++;
	}

	if(vt->cursor_y == vt->rows)
	{
		vterm_scroll(fb, vt);
		vt->cursor_y--;

		return true;
	}

	return false;
}

void draw_cursor(int x, int y, struct framebuffer *fb, struct color fg)
{
	struct font *font = get_font_data();
	volatile char *buffer = (volatile char *) fb->framebuffer;

	buffer += y * fb->pitch + x * (fb->bpp / 8);

	for(int i = 0; i < 16; i++)
	{
		for(int j = 0; j < 8; j++)
		{
			struct color color;
			unsigned char f = font->cursor_bitmap[i];

			if(f & font->mask[j])
				continue;
			else
				color = fg;
			
			uint32_t c = unpack_rgba(color, fb);
			volatile uint32_t *b = (volatile uint32_t *) ((uint32_t *) buffer + j);
			
			/* If the bpp is 32 bits, we can just blit it out */
			if(fb->bpp == 32)
				*b = c;
			else
			{
				volatile unsigned char *buf =
					(volatile unsigned char *)(buffer + j);
				int bytes = fb->bpp / 8;
				for(int i = 0; i < bytes; i++)
				{
					buf[i] = c;
					c >>= 8;
				}
			}
		}

		buffer = (void*) (((char *) buffer) + fb->pitch);
	}
}

void update_cursor(struct vterm *vt)
{
	struct framebuffer *fb = vt->fb;
	struct font *f = get_font_data();

	draw_cursor(vt->cursor_x * f->width, vt->cursor_y * f->height, fb, vt->fg);
}

void vterm_flush(struct vterm *vterm);

/*ssize_t vterm_write(const void *buffer, size_t len, struct tty *c)
{
	ssize_t written = 0;
	const char *str = buffer;
	for(size_t i = 0; i != len; str++, written++, len--)
	{
		vterm_putc(*str, c->priv);
	}
	
	vterm_flush(c->priv);
	update_cursor(c->priv);
	return written;
}*/

void do_vterm_flush(struct vterm *vterm)
{
	struct font *f = get_font_data();
	for(unsigned int i = 0; i < vterm->columns; i++)
	{
		for(unsigned int j = 0; j < vterm->rows; j++)
		{
			struct console_cell *cell = &vterm->cells[j * vterm->columns + i];

			if(vterm_is_dirty(cell))
			{
				draw_char(cell->codepoint, i * f->width, j * f->height,
					vterm->fb, cell->fg, cell->bg);
				vterm_clear_dirty(cell);
			}
		}
	}
}

void vterm_flush(struct vterm *vterm)
{
	if(vterm->multithread_enabled)
		vterm_send_message(vterm, VTERM_MESSAGE_FLUSH, NULL);
	else
		do_vterm_flush(vterm);	
}

void vterm_fill_screen(struct vterm *vterm, uint32_t character,
	struct color fg, struct color bg)
{
	for(unsigned int i = 0; i < vterm->columns; i++)
	{
		for(unsigned int j = 0; j < vterm->rows; j++)
		{
			struct console_cell *cell = &vterm->cells[j * vterm->rows + i];
			cell->codepoint = character;
			cell->bg = bg;
			cell->fg = fg;
			vterm_set_dirty(cell);
		}
	}
}

struct vterm primary_vterm = {0};

static void fb_fill_color(uint32_t color, struct framebuffer *frameb)
{
	volatile uint32_t *fb = (volatile uint32_t *) frameb->framebuffer;

	for(size_t i = 0; i < frameb->height; i++)
	{
		for(size_t j = 0; j < frameb->width; j++)
			fb[j] = color;
		fb = (volatile uint32_t *) ((char*) fb + frameb->pitch);
	}
}

void vterm_set_fgcolor(struct color c, struct vterm *vt)
{
	vt->fg = c;
}

const char *get_decimal_num(const char *buf, unsigned long *num, unsigned long len)
{
	unsigned long i = 0;

	while(isdigit(*buf) && len)
	{
		len--;
		i *= 10;
		i += *buf - '0';
		buf++;
		len--;
	}

	*num = i;

	return buf;
}

void vterm_ansi_adjust_cursor(char code, unsigned long relative, struct vterm *vt)
{
	vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
	if(relative == 0)
		relative = 1;

	switch(code)
	{
		case ANSI_CURSOR_UP:
		{
			unsigned int cy = vt->cursor_y;
			unsigned int result = cy - relative;

			/* Clamp the result */
			if(cy < result)
			{
				vt->cursor_y = 0;
			}
			else
				vt->cursor_y = result;
			break;
		}
		case ANSI_CURSOR_DOWN:
		{
			unsigned int cy = vt->cursor_y;
			unsigned int result = cy + relative;

			if(result > vt->rows - 1)
				result = vt->rows - 1;
			vt->cursor_y = result;
			break;
		}
		case ANSI_CURSOR_FORWARD:
		{
			unsigned int cx = vt->cursor_x;
			unsigned int result = cx + relative;

			if(result > vt->columns - 1)
				result = vt->columns - 1;
			vt->cursor_x = result;
			break;
		}
		case ANSI_CURSOR_BACK:
		{
			unsigned int cx = vt->cursor_x;
			unsigned int result = cx - relative;

			/* Clamp the result */
			if(cx < result)
			{
				vt->cursor_x = 0;
			}
			else
				vt->cursor_x = result;
			break;
		}
	}
}

void vterm_ansi_do_cup(unsigned long x, unsigned long y, struct vterm *vt)
{
	vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
	/* Transform x and y into 0-based values */

	x--;
	y--;

	if(x > vt->columns - 1)
		x = vt->columns - 1;
	if(y > vt->rows - 1)
		y = vt->rows - 1;

	vt->cursor_x = x;
	vt->cursor_y = y;
}

void vterm_blink_thread(void *ctx)
{
	struct vterm *vt = ctx;

	while(true)
	{
		struct font *f = get_font_data();
		mutex_lock(&vt->vt_lock);

		if(vt->blink_die)
		{
			mutex_unlock(&vt->vt_lock);
			sched_sleep_until_wake();
			mutex_lock(&vt->vt_lock);
		}

		struct color c = vt->fg;
		if(vt->blink_status == true)
		{
			vt->blink_status = false;
			c = vt->bg;
		}
		else
			vt->blink_status = true;

		draw_cursor(vt->cursor_x * f->width, vt->cursor_y * f->height,
			    vt->fb, c);

		mutex_unlock(&vt->vt_lock);
		sched_sleep_ms(500);
	}
}

void vterm_ansi_do_sgr(unsigned long n, struct vterm *vt)
{
	switch(n)
	{
		case ANSI_SGR_RESET:
		{
			vt->bg = default_bg;
			vt->fg = default_fg;
			break;
		}
		
		case ANSI_SGR_REVERSE:
		{
			struct color temp = vt->bg;
			vt->bg = vt->fg;
			vt->fg = temp;
			break;
		}

		case ANSI_SGR_DEFAULTBG:
		{
			vt->bg = default_bg;
			break;
		}
		
		case ANSI_SGR_DEFAULTFG:
		{
			vt->fg = default_fg;
			break;
		}

		case ANSI_SGR_SLOWBLINK:
		case ANSI_SGR_RAPIDBLINK:
		{
			/* NOTE: We only support one blink speed, which is
			 * 2 times/s, 120 times per minute
			*/
			/*if(!vt->blink_thread)
			{
				vt->blink_status = false;
				vt->blink_thread =
					sched_create_thread(vterm_blink_thread,
							    THREAD_KERNEL, vt);
				if(vt->blink_thread) sched_start_thread(vt->blink_thread);
			}*/
	
			/* TODO: We need a blink for text, fix */
			break;
		}

		case ANSI_SGR_BLINKOFF:
		{
			if(vt->blink_thread)
				thread_destroy(vt->blink_thread);
			break;
		}

		default:
		{
			if(n >= ANSI_SGR_SETBGMIN && n <= ANSI_SGR_SETBGMAX)
			{
				int index = n - ANSI_SGR_SETBGMIN;
				vt->bg = color_table[index];
			}
			else if(n >= ANSI_SGR_SETFGMIN && n <= ANSI_SGR_SETFGMAX)
			{
				int index = n - ANSI_SGR_SETFGMIN;
				vt->fg = color_table[index];
			}
		}
	}
}

void vterm_ansi_erase_in_line(unsigned long n, struct vterm *vt)
{
	switch(n)
	{
		/* Clear from cursor to end */
		case 0:
		{
			for(unsigned int i = vt->cursor_x; i < vt->columns; i++)
			{
				struct console_cell *c = &vt->cells[vt->cursor_y * vt->columns + i];
				c->codepoint = ' ';
				c->fg = vt->fg;
				c->bg = vt->bg;
				vterm_set_dirty(c);
			}
			break;
		}

		/* Clear from cursor to beginning */
		case 1:
		{
			unsigned int x = vt->cursor_x;

			for(unsigned int i = 0; i <= x; i++)
			{
				struct console_cell *c = &vt->cells[vt->cursor_y * vt->columns + i];
				c->codepoint = ' ';
				c->fg = vt->fg;
				c->bg = vt->bg;
				vterm_set_dirty(c);
			}
			break;
		}

		/* Clear entire line */
		case 2:
		{
			for(unsigned int i = 0; i < vt->columns; i++)
			{
				struct console_cell *c = &vt->cells[vt->cursor_y * vt->columns + i];
				c->codepoint = ' ';
				c->fg = vt->fg;
				c->bg = vt->bg;
				vterm_set_dirty(c);
			}
			break;
		}
	}
}

void vterm_ansi_erase_in_display(unsigned long n, struct vterm *vt)
{
	switch(n)
	{
		/* Cursor to end of display */
		case 0:
		{
			/* Calculate the cidx, then loop through until the end of the array */
			unsigned int cidx = vt->cursor_y * vt->columns + vt->cursor_x;
			unsigned int max = vt->rows * vt->columns;
			if(cidx + 1 < cidx)
				break;

			unsigned int iters = max - cidx;

			for(unsigned int i = 0; i < iters; i++)
			{
				struct console_cell *c = &vt->cells[cidx + i];
				c->codepoint = ' ';
				vterm_set_dirty(c);
			}

			break;
		}

		/* Cursor to start of display */
		case 1:
		{
			unsigned int cidx = vt->cursor_y * vt->columns + vt->cursor_x;

			for(unsigned int i = 0; i <= cidx; i++)
			{
				struct console_cell *c = &vt->cells[i];
				c->codepoint = ' ';
				vterm_set_dirty(c);
			}

			break;
		}

		/* Whole screen */
		case 2:
		case 3:
		{
			vterm_fill_screen(vt, ' ', vt->fg, vt->bg);
			break;
		}
	}

	vterm_flush(vt);
}

#define ARGS_NR_ELEMS		2

size_t vterm_parse_ansi(const char *buffer, size_t len, struct vterm *vt)
{
	/* len is the distance from the pointer to the end of the buffer
	 * (so we don't read past it).
	*/
	buffer++;
	size_t args_nr = 0;
	size_t args_buf_nr = ARGS_NR_ELEMS;
	const char *orig = buffer;
	/* Go to the start of the escape code, while ignoring the ESC (0x1b) */

	if(buffer[0] == ANSI_CSI)
	{
		buffer++;
		unsigned long *args = zalloc(sizeof(unsigned long) * args_buf_nr);

		buffer = get_decimal_num(buffer, &args[0], len - (buffer - orig));

		args_nr++;
	
		while(*buffer == ';' && (unsigned long) (buffer - orig) < len)
		{
			/* We have an argument */
			buffer++;

			if(args_nr == args_buf_nr)
			{
				args_buf_nr += ARGS_NR_ELEMS;
				unsigned long *old = args;
				args = realloc(args, sizeof(unsigned long) * args_buf_nr);

				if(!args)
				{
					free(old);
					/* uh oh, no memory, return 1 so we
					 * don't fall into the escape code again.
					 * It'll just print garbage the next
					 * time the loop runs
					*/
					return 1;
				}
			}

			buffer = get_decimal_num(buffer, &args[args_nr], len - (buffer - orig));
			args_nr++;

		}

		if((unsigned long) (buffer - orig) == len)
		{
			free(args);
			return len;
		}
	
		switch(*buffer)
		{
			case ANSI_CURSOR_UP:
			case ANSI_CURSOR_DOWN:
			case ANSI_CURSOR_FORWARD:
			case ANSI_CURSOR_BACK:
			{
				vterm_ansi_adjust_cursor(*buffer, args[0], vt);
				break;
			}

			case ANSI_CURSOR_PREVIOUS:
			{
				/* Do a ANSI_CURSOR_UP and set x to 0 (beginning of line) */
				vterm_ansi_adjust_cursor(ANSI_CURSOR_UP, args[0], vt);
				vt->cursor_x = 0;
				break;
			}

			case ANSI_CURSOR_NEXT_LINE:
			{
				/* Do a ANSI_CURSOR_DOWN and set x to 0 (beginning of line) */
				vterm_ansi_adjust_cursor(ANSI_CURSOR_DOWN, args[0], vt);
				vt->cursor_x = 0;
				break;
			}

			case ANSI_CURSOR_HORIZONTAL_ABS:
			{
				if(args[0] > vt->columns - 1)
					args[0] = vt->columns - 1;
				vt->cursor_x = args[0];
				break;
			}

			case ANSI_CURSOR_POS:
			case ANSI_HVP:
			{
				if(args[0] == 0)
					args[0] = 1;
				if(args[1] == 0)
					args[1] = 1;

				vterm_ansi_do_cup(args[1], args[0], vt);
				break;
			}

			case ANSI_SCROLL_UP:
			{
				for(unsigned long i = 0; i < args[0]; i++)
					vterm_scroll(vt->fb, vt);
				vterm_flush_all(vt);
				break;
			}

			case ANSI_SCROLL_DOWN:
			{
				for(unsigned long i = 0; i < args[0]; i++)
					vterm_scroll_down(vt->fb, vt);
				vterm_flush_all(vt);
				break;
			}

			case ANSI_SGR:
			{
				for(size_t i = 0; i < args_nr; i++)
					vterm_ansi_do_sgr(args[i], vt);
				break;
			}
			
			case ANSI_ERASE_IN_LINE:
			{
				vterm_ansi_erase_in_line(args[0], vt);
				break;
			}

			case ANSI_ERASE_IN_DISPLAY:
			{
				vterm_ansi_erase_in_display(args[0], vt);
				break;
			}

			case ANSI_SAVE_CURSOR:
			{
				vt->saved_x = vt->cursor_x;
				vt->saved_y = vt->cursor_y;
				break;
			}

			case ANSI_RESTORE_CURSOR:
			{
				vt->cursor_x = vt->saved_x;
				vt->cursor_y = vt->saved_y;
				break;
			}
		}
		buffer++;

		free(args);
	}

	return (buffer - orig) + 1;
}

void platform_serial_write(const char *s, size_t size);
void serial_write(const char *s, size_t size, struct serial_port *port);

ssize_t vterm_write_tty(const void *buffer, size_t size, struct tty *tty)
{
	platform_serial_write(buffer, size);
	struct vterm *vt = tty->priv;

	mutex_lock(&vt->vt_lock);
	size_t i = 0;
	const char *data = buffer;
	bool did_scroll = false;

	for (; i < size; i++)
	{
		/* Parse ANSI terminal escape codes */
		if(data[i] == ANSI_ESCAPE_CODE)
			/* Note the -1 because of the i++ in the for loop */
			i += vterm_parse_ansi(&data[i], size - i, vt) - 1;
		else
		{
			size_t codepoint_length = 0;
			utf32_t codepoint = utf8to32((utf8_t *) data + i, size - i, &codepoint_length);

			/* TODO: Detect surrogates, overlong sequences. The code I wrote before
			 * has some weird casting and returns.
			 */
			if(codepoint == UTF_INVALID_CODEPOINT)
				codepoint = '?';

			if(vterm_putc(codepoint, vt))
				did_scroll = true;

			/* We sub a 1 because we're incrementing on the for loop */
			i += codepoint_length - 1;
		}
	}
	
	if(!did_scroll)
		vterm_flush(vt);
	else
		vterm_flush_all(vt);
	update_cursor(vt);

	mutex_unlock(&vt->vt_lock);
	return i;
}

unsigned int vterm_ioctl_tty(int request, void *argp, struct tty *tty)
{
	struct vterm *vt = tty->priv;

	switch(request)
	{
		case TIOCGWINSZ:
		{
			struct winsize *win = argp;
			struct winsize kwin = {0};
			kwin.ws_row = vt->rows;
			kwin.ws_col = vt->columns;
			kwin.ws_xpixel = vt->fb->width;
			kwin.ws_ypixel = vt->fb->height;
			if(copy_to_user(win, &kwin, sizeof(struct winsize)) < 0)
				return -EFAULT;
			return 0;
		}
		default:
			return -EINVAL;
	}
}

void vterm_init(struct tty *tty)
{
	struct vterm *vt = tty->priv;

	mutex_init(&vt->vt_lock);
	mutex_init(&vt->condvar_mutex);

	tty->is_vterm = true;
	struct framebuffer *fb = get_primary_framebuffer();
	struct font *font = get_font_data();
	vt->columns = fb->width / font->width;
	vt->rows = fb->height / font->height;
	vt->fb = fb;
	vt->cells = vmalloc(vm_size_to_pages(vt->columns * vt->rows
		* sizeof(*vt->cells)), VM_TYPE_REGULAR, VM_WRITE | VM_NOEXEC);
	assert(vt->cells != NULL);

	vt->fg = default_fg;
	vt->bg = default_bg;

	assert(vt->cells != NULL);

	vterm_fill_screen(vt, ' ', vt->fg, vt->bg);

	vterm_flush(vt);

	update_cursor(vt);

	tty->read = NULL;
	tty->write = vterm_write_tty;
	tty->ioctl = vterm_ioctl_tty;

	vt->tty = tty;
}

ssize_t serial_write_tty(const void *s, size_t size, struct tty *tty)
{
	struct serial_port *port = tty->priv;

	serial_write(s, size, port);

	return size;
}

void serial_tty_init(struct tty *tty)
{
	tty->write = serial_write_tty;
	tty->priv = platform_get_main_serial();
}

void vterm_do_init(void)
{
	platform_serial_init();

	struct framebuffer *fb = get_primary_framebuffer();
	if(fb)
		tty_init(&primary_vterm, vterm_init);
	else
		tty_init(NULL, serial_tty_init);
}

struct vterm *get_current_vt(void)
{
	return &primary_vterm;
}

int vterm_receive_input(char *c)
{
	struct vterm *vt = get_current_vt();
	if(!vt)
		return -1;

	tty_received_character(vt->tty, *c);

	return 0;
}

struct key_action
{
	keycode_t key;
	char *action;
	char *shift_action;
	char *ctrl_action;
	char *alt_action;
	uint8_t flags;
};

struct key_action key_actions[] = 
{
	{KEYMAP_KEY_A, "a", "A"},
	{KEYMAP_KEY_B, "b", "B"},
	{KEYMAP_KEY_C, "c", "C", "\03"},
	{KEYMAP_KEY_D, "d", "D", "\04"},
	{KEYMAP_KEY_E, "e", "E"},
	{KEYMAP_KEY_F, "f", "F"},
	{KEYMAP_KEY_G, "g", "G"},
	{KEYMAP_KEY_H, "h", "H", "\b"},
	{KEYMAP_KEY_I, "i", "I"},
	{KEYMAP_KEY_J, "j", "J"},
	{KEYMAP_KEY_K, "k", "K"},
	{KEYMAP_KEY_L, "l", "L"},
	{KEYMAP_KEY_M, "m", "M"},
	{KEYMAP_KEY_N, "n", "N"},
	{KEYMAP_KEY_O, "o", "O"},
	{KEYMAP_KEY_P, "p", "P"},
	{KEYMAP_KEY_Q, "q", "Q"},
	{KEYMAP_KEY_R, "r", "R"},
	{KEYMAP_KEY_S, "s", "S"},
	{KEYMAP_KEY_T, "t", "T"},
	{KEYMAP_KEY_U, "u", "U"},
	{KEYMAP_KEY_V, "v", "V"},
	{KEYMAP_KEY_X, "x", "X"},
	{KEYMAP_KEY_W, "w", "W"},
	{KEYMAP_KEY_Y, "y", "Y"},
	{KEYMAP_KEY_Z, "z", "Z"},
	{KEYMAP_KEY_0, "0", ")"},
	{KEYMAP_KEY_1, "1", "!"},
	{KEYMAP_KEY_2, "2", "@"},
	{KEYMAP_KEY_3, "3", "#"},
	{KEYMAP_KEY_4, "4", "$"},
	{KEYMAP_KEY_5, "5", "%"},
	{KEYMAP_KEY_6, "6", "^"},
	{KEYMAP_KEY_7, "7", "&"},
	{KEYMAP_KEY_8, "8", "*"},
	{KEYMAP_KEY_9, "9", "("},
	{KEYMAP_KEY_COMMA, ",", "<"},
	{KEYMAP_KEY_DOT, ".", ">"},
	{KEYMAP_KEY_KEYPAD_0, "0"},
	{KEYMAP_KEY_KEYPAD_1, "1"},
	{KEYMAP_KEY_KEYPAD_2, "2"},
	{KEYMAP_KEY_KEYPAD_3, "3"},
	{KEYMAP_KEY_KEYPAD_4, "4"},
	{KEYMAP_KEY_KEYPAD_5, "5"},
	{KEYMAP_KEY_KEYPAD_6, "6"},
	{KEYMAP_KEY_KEYPAD_7, "7"},
	{KEYMAP_KEY_KEYPAD_8, "8"},
	{KEYMAP_KEY_KEYPAD_9, "9"},
	{KEYMAP_KEY_MINUS, "-", "_"},
	{KEYMAP_KEY_EQUALS, "=", "+"},
	{KEYMAP_KEY_LEFTBRACE, "[", "{"},
	{KEYMAP_KEY_RIGHTBRACE, "]", "}"},
	{KEYMAP_KEY_ENTER, "\n"},
	{KEYMAP_KEY_SEMICOLON, ";", ":"},
	{KEYMAP_KEY_GRAVE, "`", "~"},
	{KEYMAP_KEY_TAB, "\t"},
	{KEYMAP_KEY_APOSTROPHE, "'", "\""},
	{KEYMAP_KEY_SLASH, "/", "?"},
	{KEYMAP_KEY_BACKSLASH, "|"},
	{KEYMAP_KEY_BACKSPACE, "\x7f"},
	{KEYMAP_KEY_KEYPAD_DOT, "."},
	{KEYMAP_KEY_KEYPAD_SLASH, "/"},
	{KEYMAP_KEY_KEYPAD_ASTERISK, "*"},
	{KEYMAP_KEY_KEYPAD_MINUS, "-"},
	{KEYMAP_KEY_KEYPAD_PLUS, "+"},
	{KEYMAP_KEY_KEYPAD_ENTER, "\n"},
	{KEYMAP_KEY_SPACE, " ", " "}
};

struct key_action pt_pt_key_actions[] = 
{
	{KEYMAP_KEY_A, "a", "A"},
	{KEYMAP_KEY_B, "b", "B"},
	{KEYMAP_KEY_C, "c", "C", "\03"},
	{KEYMAP_KEY_D, "d", "D", "\04"},
	{KEYMAP_KEY_E, "e", "E"},
	{KEYMAP_KEY_F, "f", "F"},
	{KEYMAP_KEY_G, "g", "G"},
	{KEYMAP_KEY_H, "h", "H", "\b"},
	{KEYMAP_KEY_I, "i", "I"},
	{KEYMAP_KEY_J, "j", "J"},
	{KEYMAP_KEY_K, "k", "K"},
	{KEYMAP_KEY_L, "l", "L"},
	{KEYMAP_KEY_M, "m", "M"},
	{KEYMAP_KEY_N, "n", "N"},
	{KEYMAP_KEY_O, "o", "O"},
	{KEYMAP_KEY_P, "p", "P"},
	{KEYMAP_KEY_Q, "q", "Q"},
	{KEYMAP_KEY_R, "r", "R"},
	{KEYMAP_KEY_S, "s", "S"},
	{KEYMAP_KEY_T, "t", "T"},
	{KEYMAP_KEY_U, "u", "U"},
	{KEYMAP_KEY_V, "v", "V"},
	{KEYMAP_KEY_X, "x", "X"},
	{KEYMAP_KEY_W, "w", "W"},
	{KEYMAP_KEY_Y, "y", "Y"},
	{KEYMAP_KEY_Z, "z", "Z"},
	{KEYMAP_KEY_0, "0", "=", NULL, "}"},
	{KEYMAP_KEY_1, "1", "!"},
	{KEYMAP_KEY_2, "2", "\"", NULL, "@"},
	{KEYMAP_KEY_3, "3", "#", NULL, "£"},
	{KEYMAP_KEY_4, "4", "$", NULL, "§"},
	{KEYMAP_KEY_5, "5", "%", NULL, "€"},
	{KEYMAP_KEY_6, "6", "&"},
	{KEYMAP_KEY_7, "7", "/", NULL, "{"},
	{KEYMAP_KEY_8, "8", "(", NULL, "["},
	{KEYMAP_KEY_9, "9", ")", NULL, "]"},
	{KEYMAP_KEY_COMMA, ",", ";"},
	{KEYMAP_KEY_DOT, ".", ":"},
	{KEYMAP_KEY_KEYPAD_0, "0"},
	{KEYMAP_KEY_KEYPAD_1, "1"},
	{KEYMAP_KEY_KEYPAD_2, "2"},
	{KEYMAP_KEY_KEYPAD_3, "3"},
	{KEYMAP_KEY_KEYPAD_4, "4"},
	{KEYMAP_KEY_KEYPAD_5, "5"},
	{KEYMAP_KEY_KEYPAD_6, "6"},
	{KEYMAP_KEY_KEYPAD_7, "7"},
	{KEYMAP_KEY_KEYPAD_8, "8"},
	{KEYMAP_KEY_KEYPAD_9, "9"},
	{KEYMAP_KEY_MINUS, "'", "?"},
	{KEYMAP_KEY_EQUALS, "«", "»"},
	{KEYMAP_KEY_LEFTBRACE, "+", "*"},
	{KEYMAP_KEY_RIGHTBRACE, "´", "`"},
	{KEYMAP_KEY_ENTER, "\n"},
	{KEYMAP_KEY_SEMICOLON, "ç", "Ç"},
	{KEYMAP_KEY_GRAVE, "\\", "|"},
	{KEYMAP_KEY_TAB, "\t"},
	{KEYMAP_KEY_APOSTROPHE, "º", "ª"},
	{KEYMAP_KEY_SLASH, "-", "_"},
	{KEYMAP_KEY_BACKSLASH, "|"},
	{KEYMAP_KEY_BACKSPACE, "\x7f"},
	{KEYMAP_KEY_KEYPAD_DOT, "."},
	{KEYMAP_KEY_KEYPAD_SLASH, "/"},
	{KEYMAP_KEY_KEYPAD_ASTERISK, "*"},
	{KEYMAP_KEY_KEYPAD_MINUS, "-"},
	{KEYMAP_KEY_KEYPAD_PLUS, "+"},
	{KEYMAP_KEY_KEYPAD_ENTER, "\n"},
	{KEYMAP_KEY_SPACE, " ", " "},
	{KEYMAP_102ND, "<", ">"}
};

const size_t nr_actions = sizeof(key_actions) / sizeof(key_actions[0]);

void __vterm_receive_input(void *p)
{
	char *s = p;
	vterm_receive_input(s);
}

void sched_dump_threads(void);

int vterm_handle_key(struct vterm *vt, struct input_device *dev, struct input_event *ev)
{
	/* We have no interest in release events */
	if(!(ev->flags & INPUT_EVENT_FLAG_PRESSED))
		return 0;

	/* Don't have this enabled by default */
	if(0 && ev->code == KEYMAP_KEY_KEYPAD_NUMLCK)
		sched_dump_threads();

	struct key_action *acts = pt_pt_key_actions;
	struct key_action *desired_action = NULL;

	for(size_t i = 0; i <= nr_actions; i++)
	{
		if(acts[i].key == ev->code)
		{
			desired_action = &acts[i];
			break;
		}
	}

	/* Not mapped */
	if(!desired_action)
	{
		return 0;
	}

	char *action_string = NULL;

	if(unlikely(dev->state.shift_pressed || dev->state.caps_enabled))
	{
		action_string = desired_action->shift_action;
	}
	else if(unlikely(dev->state.ctrl_pressed))
	{
		action_string = desired_action->ctrl_action;
	}
	else if(unlikely(dev->state.alt_pressed))
	{
		action_string = desired_action->alt_action;
	}
	else
	{
		action_string = desired_action->action;
	}

	if(likely(action_string))
	{
		struct dpc_work w;
		w.context = action_string;
		w.funcptr = __vterm_receive_input;
		w.next = NULL;
		dpc_schedule_work(&w, DPC_PRIORITY_MEDIUM);
	}

	return 0;
}

int vterm_submit_event(struct input_device *dev, struct input_event *ev)
{
	struct vterm *vt = get_current_vt();
	if(!vt)
		return -1;

	return vterm_handle_key(vt, dev, ev);
}

void vterm_handle_message(struct vterm_message *msg, struct vterm *vt)
{
	switch(msg->message)
	{
		case VTERM_MESSAGE_FLUSH:
			do_vterm_flush(vt);
			break;
		case VTERM_MESSAGE_FLUSH_ALL:
			do_vterm_flush_all(vt);
			break;
		case VTERM_MESSAGE_DIE:
			sched_sleep_until_wake();
			do_vterm_flush_all(vt);
			break;
	}
}

void vterm_handle_messages(struct vterm *vt)
{
	struct vterm_message *msg = vt->msgs;
	while(msg != NULL)
	{
		struct vterm_message *old = msg;
		vterm_handle_message(msg, vt);
		msg = msg->next;

		free(old);
	}

	vt->msgs = NULL;
}

void vterm_render_thread(void *arg)
{
	struct vterm *vt = arg;

	mutex_lock(&vt->condvar_mutex);

	while(true)
	{
		condvar_wait(&vt->condvar, &vt->condvar_mutex);
		vterm_handle_messages(vt);
	}
}

void vterm_switch_to_multithread(struct vterm *vt)
{
	vt->render_thread = sched_create_thread(vterm_render_thread, THREAD_KERNEL, vt);

	assert(vt->render_thread != NULL);

	vt->multithread_enabled = true;

	vt->render_thread->priority = SCHED_PRIO_NORMAL;

	sched_start_thread(vt->render_thread);
}

void vt_init_blink(void)
{
	struct vterm *vt = &primary_vterm;
	if(!vt->fb)
		return;
	if(!vt->blink_thread)
	{
		vt->blink_status = false;
		vt->blink_thread =
			sched_create_thread(vterm_blink_thread,
					    THREAD_KERNEL, vt);
		if(vt->blink_thread) sched_start_thread(vt->blink_thread);
	}

	vterm_switch_to_multithread(vt);
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(vt_init_blink);

void vterm_panic(void)
{
	primary_vterm.multithread_enabled = false;
	
	if(primary_vterm.tty)
		primary_vterm.tty->lock.counter = 0;
}

void vterm_release_video(struct vterm *vt)
{
	mutex_lock(&vt->vt_lock);
	
	vt->blink_die = true;
	vt->blink_status = true;

	struct font *f = get_font_data();
	draw_cursor(vt->cursor_x * f->width, vt->cursor_y * f->height,
			    vt->fb, vt->fg);

	vterm_send_message(vt, VTERM_MESSAGE_DIE, NULL);

	/* Wait 10ms for the render thread to stop */
	sched_sleep_ms(10);

	mutex_unlock(&vt->vt_lock);

}

void vterm_get_video(struct vterm *vt)
{
	mutex_lock(&vt->vt_lock);

	vt->blink_die = false;

	thread_wake_up(vt->blink_thread);

	thread_wake_up(vt->render_thread);

	mutex_unlock(&vt->vt_lock);

}
