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

#include <onyx/tty.h>
#include <onyx/framebuffer.h>
#include <onyx/font.h>
#include <onyx/vm.h>

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

struct console_cell
{
	uint32_t codepoint;
	struct color bg;
	struct color fg;
	unsigned long dirty;	
};

struct vterm
{
	unsigned int columns;
	unsigned int rows;
	unsigned int cursor_x, cursor_y;
	struct framebuffer *fb;
	struct console_cell *cells;
	struct color fg;
	struct color bg;
	char keyboard_buffer[2048];
	unsigned int keyboard_pos;
	struct tty *tty;
};

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

void vterm_flush_all(struct vterm *vterm)
{
	struct font *f = get_font_data();
	for(unsigned int i = 0; i < vterm->columns; i++)
	{
		for(unsigned int j = 0; j < vterm->rows; j++)
		{
			struct console_cell *cell = &vterm->cells[j * vterm->columns + i];
			draw_char(cell->codepoint, i * f->width, j * f->height,
				vterm->fb, cell->fg, cell->bg);
			cell->dirty = 0;
		}
	}
}

void vterm_scroll(struct framebuffer *fb, struct vterm *vt)
{
	memcpy(vt->cells, vt->cells + vt->columns, sizeof(struct console_cell)
		* (vt->rows-1) * vt->columns);

	for(unsigned int i = 0; i < vt->columns; i++)
	{
		struct console_cell *c = &vt->cells[(vt->rows-1) * vt->columns + i];
		c->codepoint = ' ';
		c->bg = default_bg;
		c->fg = default_fg;
	}

	//vterm_flush_all(vt);
}

void vterm_set_char(char c, unsigned int x, unsigned int y, struct color fg,
	struct color bg, struct vterm *vterm)
{
	struct console_cell *cell = &vterm->cells[y * vterm->columns + x];
	cell->codepoint = c;
	cell->fg = fg;
	cell->bg = bg;
	cell->dirty = 1;
}

bool vterm_putc(char c, struct vterm *vt)
{
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
		vterm_set_char(' ', vt->cursor_x, vt->cursor_y, vt->fg, vt->bg, vt);
		vt->cursor_x = 0;
		vt->cursor_y++;
	}
	else if(c == '\b')
	{
		if(vt->cursor_x == 0)
			return false;
		
		vterm_set_char(' ', vt->cursor_x, vt->cursor_y, vt->fg, vt->bg, vt);
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

void draw_cursor(int x, int y, struct framebuffer *fb)
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
				color = default_bg;
			else
				color = default_fg;
			
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

	draw_cursor(vt->cursor_x * f->width, vt->cursor_y * f->height, fb);
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

void vterm_flush(struct vterm *vterm)
{
	struct font *f = get_font_data();
	for(unsigned int i = 0; i < vterm->columns; i++)
	{
		for(unsigned int j = 0; j < vterm->rows; j++)
		{
			struct console_cell *cell = &vterm->cells[j * vterm->columns + i];

			if(cell->dirty)
			{
				draw_char(cell->codepoint, i * f->width, j * f->height,
					vterm->fb, cell->fg, cell->bg);
				cell->dirty = 0;
			}
		}
	}
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
			cell->dirty = 1;
		}
	}

	vterm_flush(vterm);
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

ssize_t vterm_write_tty(void *buffer, size_t size, struct tty *tty)
{
	struct vterm *vt = tty->priv;

	size_t i = 0;
	char *data = buffer;
	bool did_scroll = false;

	for (; i < size; i++)
	{
		/* Parse ANSI terminal escape codes */
		if(!memcmp(&data[i], ANSI_COLOR_RED, strlen(ANSI_COLOR_RED)))
		{
			vterm_set_fgcolor(vterm_default_red, vt);
			i += strlen(ANSI_COLOR_RED);
			if(i >= size) break;
		}
		
		if(!memcmp(&data[i], ANSI_COLOR_GREEN, strlen(ANSI_COLOR_GREEN)))
		{
			vterm_set_fgcolor(vterm_default_green, vt);
			i += strlen(ANSI_COLOR_GREEN);
			if(i >= size) break;			
		}
		
		if(!memcmp(&data[i], ANSI_COLOR_YELLOW, strlen(ANSI_COLOR_YELLOW)))
		{
			vterm_set_fgcolor(vterm_default_yellow, vt);
			i += strlen(ANSI_COLOR_YELLOW);
			if(i >= size) break;
		
		}
		if(!memcmp(&data[i], ANSI_COLOR_BLUE, strlen(ANSI_COLOR_BLUE)))
		{
			vterm_set_fgcolor(vterm_default_blue, vt);
			i += strlen(ANSI_COLOR_BLUE);
			if(i >= size) break;
		}
		
		if(!memcmp(&data[i], ANSI_COLOR_MAGENTA, strlen(ANSI_COLOR_MAGENTA)))
		{
			vterm_set_fgcolor(vterm_default_magenta, vt);
			i += strlen(ANSI_COLOR_MAGENTA);
			if(i >= size) break;
		}
		
		if(!memcmp(&data[i], ANSI_COLOR_CYAN, strlen(ANSI_COLOR_CYAN)))
		{
			vterm_set_fgcolor(vterm_default_cyan, vt);
			i += strlen(ANSI_COLOR_CYAN);
			if(i >= size) break;
		}
		
		if(!memcmp(&data[i], ANSI_COLOR_RESET, strlen(ANSI_COLOR_RESET)))
		{
			vterm_set_fgcolor(default_fg, vt);
			i += strlen(ANSI_COLOR_RESET);
			if(i >= size) break;
		}

		if(vterm_putc(data[i], vt))
			did_scroll = true;
	
	}
	
	if(!did_scroll)
		vterm_flush(vt);
	else
		vterm_flush_all(vt);
	update_cursor(vt);

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
				return errno = EFAULT, -1;
			return 0;
		}
		default:
			return errno = EINVAL, -1;
	}
}

void vterm_init(struct tty *tty)
{
	struct vterm *vt = tty->priv;
	struct framebuffer *fb = get_primary_framebuffer();
	struct font *font = get_font_data();
	vt->columns = fb->width / font->width;
	vt->rows = fb->height / font->height;
	vt->fb = fb;
	vt->cells = zalloc(vt->columns * vt->rows
		* sizeof(*vt->cells));

	vt->fg = default_fg;
	vt->bg = default_bg;

	assert(vt->cells != NULL);

	vterm_fill_screen(vt, ' ', vt->fg, vt->bg);

	update_cursor(vt);

	tty->read = NULL;
	tty->write = vterm_write_tty;
	tty->ioctl = vterm_ioctl_tty;

	vt->tty = tty;
}

void vterm_do_init(void)
{
	tty_init(&primary_vterm, vterm_init);
}

struct vterm *get_current_vt(void)
{
	return &primary_vterm;
}

int vterm_recieve_input(char c)
{
	struct vterm *vt = get_current_vt();
	if(!vt)
		return -1;

	tty_recieved_character(vt->tty, c);

	return 0;
}