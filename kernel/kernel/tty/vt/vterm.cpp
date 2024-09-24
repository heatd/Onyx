/*
 * Copyright (c) 2018 - 2024 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <onyx/console.h>
#include <onyx/dpc.h>
#include <onyx/font.h>
#include <onyx/framebuffer.h>
#include <onyx/init.h>
#include <onyx/input/device.h>
#include <onyx/input/event.h>
#include <onyx/input/keys.h>
#include <onyx/input/state.h>
#include <onyx/intrinsics.h>
#include <onyx/page.h>
#include <onyx/scheduler.h>
#include <onyx/semaphore.h>
#include <onyx/serial.h>
#include <onyx/thread.h>
#include <onyx/tty.h>
#include <onyx/types.h>
#include <onyx/utf8.h>
#include <onyx/vm.h>

#include <uapi/ioctls.h>

#include <onyx/utility.hpp>

struct tty;

struct color
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
};

static struct color default_fg = {204, 204, 204};
static struct color default_bg = {};

const struct color color_table[] = {
    {.r = 0, .g = 0, .b = 0},     /* Black */
    {.r = 205, .g = 49, .b = 49}, /* Red */
    {.r = 19, .g = 161, .b = 14}, /* Green */
    {229, 229, 16},               /* Yellow */
    {36, 114, 200},               /* Blue */
    {188, 63, 188},               /* Magenta */
    {17, 168, 205},               /* Cyan */
    {204, 204, 204}               /* White */
};

#define VTERM_CONSOLE_CELL_DIRTY        (1 << 0)
#define VTERM_CONSOLE_CELL_CONTINUATION (1 << 1)

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

#define VTERM_MESSAGE_FLUSH     1
#define VTERM_MESSAGE_FLUSH_ALL 2
#define VTERM_MESSAGE_DIE       3

struct vterm_message
{
    unsigned long message;
    void *ctx;
    struct vterm_message *next;
};

enum Gx_type
{
    Gx_LATIN1,
    Gx_GRAPH,
};

/* Translations from Linux */
static const unsigned short translations[][256] = {
    /* 8-bit Latin-1 mapped to Unicode -- trivial mapping */
    [Gx_LATIN1] = {0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009,
                   0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011, 0x0012, 0x0013,
                   0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x001a, 0x001b, 0x001c, 0x001d,
                   0x001e, 0x001f, 0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
                   0x0028, 0x0029, 0x002a, 0x002b, 0x002c, 0x002d, 0x002e, 0x002f, 0x0030, 0x0031,
                   0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003a, 0x003b,
                   0x003c, 0x003d, 0x003e, 0x003f, 0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045,
                   0x0046, 0x0047, 0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
                   0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059,
                   0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x005f, 0x0060, 0x0061, 0x0062, 0x0063,
                   0x0064, 0x0065, 0x0066, 0x0067, 0x0068, 0x0069, 0x006a, 0x006b, 0x006c, 0x006d,
                   0x006e, 0x006f, 0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
                   0x0078, 0x0079, 0x007a, 0x007b, 0x007c, 0x007d, 0x007e, 0x007f, 0x0080, 0x0081,
                   0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, 0x0088, 0x0089, 0x008a, 0x008b,
                   0x008c, 0x008d, 0x008e, 0x008f, 0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095,
                   0x0096, 0x0097, 0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,
                   0x00a0, 0x00a1, 0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7, 0x00a8, 0x00a9,
                   0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af, 0x00b0, 0x00b1, 0x00b2, 0x00b3,
                   0x00b4, 0x00b5, 0x00b6, 0x00b7, 0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc, 0x00bd,
                   0x00be, 0x00bf, 0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
                   0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf, 0x00d0, 0x00d1,
                   0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d7, 0x00d8, 0x00d9, 0x00da, 0x00db,
                   0x00dc, 0x00dd, 0x00de, 0x00df, 0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5,
                   0x00e6, 0x00e7, 0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,
                   0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7, 0x00f8, 0x00f9,
                   0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff},
    /* VT100 graphics mapped to Unicode */
    [Gx_GRAPH] = {0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008, 0x0009,
                  0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f, 0x0010, 0x0011, 0x0012, 0x0013,
                  0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x001a, 0x001b, 0x001c, 0x001d,
                  0x001e, 0x001f, 0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
                  0x0028, 0x0029, 0x002a, 0x2192, 0x2190, 0x2191, 0x2193, 0x002f, 0x2588, 0x0031,
                  0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003a, 0x003b,
                  0x003c, 0x003d, 0x003e, 0x003f, 0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045,
                  0x0046, 0x0047, 0x0048, 0x0049, 0x004a, 0x004b, 0x004c, 0x004d, 0x004e, 0x004f,
                  0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057, 0x0058, 0x0059,
                  0x005a, 0x005b, 0x005c, 0x005d, 0x005e, 0x00a0, 0x25c6, 0x2592, 0x2409, 0x240c,
                  0x240d, 0x240a, 0x00b0, 0x00b1, 0x2591, 0x240b, 0x2518, 0x2510, 0x250c, 0x2514,
                  0x253c, 0x23ba, 0x23bb, 0x2500, 0x23bc, 0x23bd, 0x251c, 0x2524, 0x2534, 0x252c,
                  0x2502, 0x2264, 0x2265, 0x03c0, 0x2260, 0x00a3, 0x00b7, 0x007f, 0x0080, 0x0081,
                  0x0082, 0x0083, 0x0084, 0x0085, 0x0086, 0x0087, 0x0088, 0x0089, 0x008a, 0x008b,
                  0x008c, 0x008d, 0x008e, 0x008f, 0x0090, 0x0091, 0x0092, 0x0093, 0x0094, 0x0095,
                  0x0096, 0x0097, 0x0098, 0x0099, 0x009a, 0x009b, 0x009c, 0x009d, 0x009e, 0x009f,
                  0x00a0, 0x00a1, 0x00a2, 0x00a3, 0x00a4, 0x00a5, 0x00a6, 0x00a7, 0x00a8, 0x00a9,
                  0x00aa, 0x00ab, 0x00ac, 0x00ad, 0x00ae, 0x00af, 0x00b0, 0x00b1, 0x00b2, 0x00b3,
                  0x00b4, 0x00b5, 0x00b6, 0x00b7, 0x00b8, 0x00b9, 0x00ba, 0x00bb, 0x00bc, 0x00bd,
                  0x00be, 0x00bf, 0x00c0, 0x00c1, 0x00c2, 0x00c3, 0x00c4, 0x00c5, 0x00c6, 0x00c7,
                  0x00c8, 0x00c9, 0x00ca, 0x00cb, 0x00cc, 0x00cd, 0x00ce, 0x00cf, 0x00d0, 0x00d1,
                  0x00d2, 0x00d3, 0x00d4, 0x00d5, 0x00d6, 0x00d7, 0x00d8, 0x00d9, 0x00da, 0x00db,
                  0x00dc, 0x00dd, 0x00de, 0x00df, 0x00e0, 0x00e1, 0x00e2, 0x00e3, 0x00e4, 0x00e5,
                  0x00e6, 0x00e7, 0x00e8, 0x00e9, 0x00ea, 0x00eb, 0x00ec, 0x00ed, 0x00ee, 0x00ef,
                  0x00f0, 0x00f1, 0x00f2, 0x00f3, 0x00f4, 0x00f5, 0x00f6, 0x00f7, 0x00f8, 0x00f9,
                  0x00fa, 0x00fb, 0x00fc, 0x00fd, 0x00fe, 0x00ff},
};

#define MAX_ARGS 4
struct vterm
{
    struct mutex vt_lock;
    unsigned int columns;
    unsigned int rows;
    unsigned int cursor_x, cursor_y;
    unsigned int top, bottom; /* For the scrolling region */
    struct framebuffer *fb;
    struct console_cell *cells;
    struct color fg;
    struct color bg;
    struct thread *blink_thread;
    bool blink_status;             /* true = visible, false = not */
    unsigned int saved_x, saved_y; /* Used by ANSI_SAVE/RESTORE_CURSOR */
    bool blink_die;
    struct tty *tty;
    bool multithread_enabled;
    struct thread *render_thread;
    struct cond condvar;
    struct mutex condvar_mutex;
    struct vterm_message *msgs;
    bool reversed;
    bool flush_all;
    bool numlck;
    unsigned long *dirty_row_bitmap;
    unsigned int bitmap_size;
    enum Gx_type gx[2];
    u8 charset;

    // Buffer used for any multibyte buffering for utf8
    char multibyte_buffer[10];

    bool in_escape;
    bool seq_finished;
    bool in_csi;
    bool in_dec;

    struct
    {
        bool dec_private;
        bool in_arg;
        unsigned long args[MAX_ARGS];
        size_t nr_args;
        char escape_character;
    } csi_data;

    size_t do_escape(const char *buffer, size_t length);
    utf32_t last_char; // for REP (CSI Ps b)

private:
    void process_escape_char(char c);
    void reset_escape_status();
    void process_csi_char(char c);
    void process_dec_char(char c);
    void insert_blank(unsigned long nr);
    void do_device_attributes(unsigned long nr);
    void do_device_status_report(unsigned long nr);
    void do_dec_command(char c);
    void do_csi_command(char escape);
    void do_generic_escape(char escape);
    void insert_lines(unsigned long nr);
    void repeat_last(unsigned long nr);
    void do_ri();
    void do_nl();
    void do_cr();
    void delete_lines(unsigned long nr);
};

void vterm_append_msg(struct vterm *vterm, struct vterm_message *msg) ACQUIRE(vterm->condvar_mutex)
{
    mutex_lock(&vterm->condvar_mutex);

    struct vterm_message **pp = &vterm->msgs;

    while (*pp)
    {
        pp = &(*pp)->next;
    }

    *pp = msg;
}

void vterm_send_message(struct vterm *vterm, unsigned long message, void *ctx)
{
    struct vterm_message *msg = (vterm_message *) zalloc(sizeof(*msg));

    /* TODO: Maybe don't crash here? */
    assert(msg != NULL);

    msg->message = message;
    msg->ctx = ctx;
    msg->next = NULL;

    vterm_append_msg(vterm, msg);

    condvar_signal(&vterm->condvar);

    mutex_unlock(&vterm->condvar_mutex);
}

#define LONG_SIZE_BITS __LONG_WIDTH__

static inline void vterm_dirty_cell(unsigned int x, unsigned int y, struct vterm *vt)
{
    struct console_cell *cell = &vt->cells[y * vt->columns + x];
    vterm_set_dirty(cell);
    vt->dirty_row_bitmap[y / LONG_SIZE_BITS] |= (1UL << (y % LONG_SIZE_BITS));
}

static inline uint32_t unpack_rgba(struct color color, struct framebuffer *fb)
{
    uint32_t c = ((color.r << fb->color.red_shift) & fb->color.red_mask) |
                 ((color.g << fb->color.green_shift) & fb->color.green_mask) |
                 ((color.b << fb->color.blue_shift) & fb->color.blue_mask);

    return c;
}

static void draw_char(uint32_t c, unsigned int x, unsigned int y, struct framebuffer *fb,
                      struct color fg, struct color bg)
{
    struct font *font = get_font_data();

    c = font->utf2char(c);
    if (c >= font->chars)
        c = '?';

    volatile char *buffer = (volatile char *) fb->framebuffer;

    buffer += y * fb->pitch + x * (fb->bpp / 8);

    unsigned int font_start = c * font->height;

    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            struct color color;
            unsigned char f = font->font_bitmap[font_start + i];

            if (f & font->mask[j])
                color = fg;
            else
                color = bg;

            uint32_t color_u32 = unpack_rgba(color, fb);
            volatile uint32_t *b = (volatile uint32_t *) ((uint32_t *) buffer + j);

            /* If the bpp is 32 bits, we can just blit it out */
            if (fb->bpp == 32)
                mov_non_temporal(b, color_u32);
            else
            {
                volatile unsigned char *buf = (volatile unsigned char *) (buffer + j);
                int bytes = fb->bpp / 8;
                for (int k = 0; k < bytes; k++)
                {
                    buf[k] = color_u32;
                    color_u32 >>= 8;
                }
            }
        }

        buffer = (volatile char *) (((char *) buffer) + fb->pitch);
    }
}

void do_vterm_flush_all(struct vterm *vterm)
{
    struct font *f = get_font_data();
    for (unsigned int i = 0; i < vterm->columns; i++)
    {
        for (unsigned int j = 0; j < vterm->rows; j++)
        {
            struct console_cell *cell = &vterm->cells[j * vterm->columns + i];
            draw_char(cell->codepoint, i * f->width, j * f->height, vterm->fb, cell->fg, cell->bg);
            vterm_clear_dirty(cell);
        }
    }
}

void vterm_flush_all(struct vterm *vterm)
{
    if (vterm->multithread_enabled)
        vterm_send_message(vterm, VTERM_MESSAGE_FLUSH_ALL, NULL);
    else
        do_vterm_flush_all(vterm);
}

static inline bool same_colour(const struct color *c1, const struct color *c2)
{
    return c1->a == c2->a && c1->r == c2->r && c1->g == c2->g && c1->b == c2->b;
}

static void vterm_clear_range(struct vterm *vt, unsigned int start_x, unsigned int start_y,
                              unsigned int end_x, unsigned int end_y)
{
    unsigned int x = start_x, y = start_y;
    unsigned int len;

    if (start_y == end_y)
        len = end_x - start_x;
    else
        len = (vt->columns - start_x) + end_x + (end_y - start_y - 1) * vt->columns;

    struct console_cell *cell = vt->cells + (y * vt->columns) + x;

    for (unsigned int i = 0; i < len; i++)
    {
        CHECK(cell < vt->cells + (vt->columns * vt->rows));
        if (cell->codepoint != ' ' || !same_colour(&cell->bg, &vt->bg) ||
            !same_colour(&cell->fg, &vt->fg))
        {
            cell->codepoint = ' ';
            cell->bg = vt->bg;
            cell->fg = vt->fg;
            vterm_dirty_cell(x, y, vt);
        }

        cell++;
        if (unlikely(++x == vt->columns))
        {
            x = 0;
            y++;
        }
    }
}

static void __vterm_scroll(struct framebuffer *fb, struct vterm *vt, unsigned int nr_lines,
                           unsigned int top, unsigned int bottom)
{
    if (top + nr_lines >= bottom)
        nr_lines = (bottom - top) - 1;

    unsigned int start = vt->columns * top;
    unsigned int dest = vt->columns * (top + nr_lines);
    unsigned int end = vt->columns * (bottom - nr_lines);
    unsigned int x = 0, y = top;

    if (bottom > vt->rows || top >= bottom || nr_lines < 1)
        return;

    for (unsigned int i = 0; i < end - start; i++)
    {
        struct console_cell *dst = vt->cells + start + i;
        struct console_cell *src = vt->cells + dest + i;
        if (dst->codepoint != src->codepoint || !same_colour(&dst->bg, &src->bg) ||
            !same_colour(&dst->fg, &src->fg))
            vterm_dirty_cell(x, y, vt);
        dst->bg = src->bg;
        dst->fg = src->fg;
        dst->codepoint = src->codepoint;
        if (++x == vt->columns)
        {
            x = 0;
            y++;
        }
    }

    vterm_clear_range(vt, 0, bottom - nr_lines, 0, bottom);
}

static void vterm_scroll(struct framebuffer *fb, struct vterm *vt)
{
    __vterm_scroll(fb, vt, 1, vt->top, vt->bottom);
}

static void __vterm_scroll_down(struct framebuffer *fb, struct vterm *vt, unsigned int nr,
                                unsigned int top, unsigned int bottom)
{
    unsigned int src, clear, dst;
    src = clear = top * vt->columns;
    dst = (top + nr) * vt->columns;

    memmove(vt->cells + dst, vt->cells + src,
            (bottom - top - nr) * vt->columns * sizeof(struct console_cell));
    for (unsigned int i = 0; i < vt->columns * nr; i++)
    {
        struct console_cell *c = &vt->cells[clear + i];
        c->codepoint = ' ';
        c->bg = vt->bg;
        c->fg = vt->fg;
    }
}

static void vterm_scroll_down(struct framebuffer *fb, struct vterm *vt)
{
    __vterm_scroll_down(fb, vt, 1, vt->top, vt->bottom);
}

static inline bool vterm_needs_dirty(struct console_cell *cell, utf32_t c, struct color fg,
                                     struct color bg)
{
    return c != cell->codepoint || !same_colour(&fg, &cell->fg) || !same_colour(&bg, &cell->bg);
}

void vterm_set_char(utf32_t c, unsigned int x, unsigned int y, struct color fg, struct color bg,
                    struct vterm *vterm)
{
    struct console_cell *cell = &vterm->cells[y * vterm->columns + x];
    vterm_dirty_cell(x, y, vterm);
    if (c < 256)
        c = translations[vterm->gx[vterm->charset]][c];
    cell->codepoint = c;
    cell->fg = fg;
    cell->bg = bg;
}

bool vterm_putc(utf32_t c, struct vterm *vt)
{
    vt->last_char = c;
    if (c == '\0')
        return false;

    // TODO: Special behavior?
    if (c == '\a')
        return false;

    if (c == '\016')
    {
        /* Shift-out */
        vt->charset = 1;
        return false;
    }

    if (c == '\017')
    {
        /* Shift-in */
        vt->charset = 0;
        return false;
    }

    if (c == '\t')
    {
        // TODO: Support variable tab sizes
        unsigned int next_stop = ALIGN_TO(vt->cursor_x + 1, 8);
        if (next_stop >= vt->columns)
            next_stop = vt->columns - 1;

        vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);

        vt->cursor_x = next_stop;
        return false;
    }

    struct framebuffer *fb = vt->fb;

    if (c == '\n')
    {
        vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
        vt->cursor_y++;
    }
    else if (c == '\r')
    {
        vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
        vt->cursor_x = 0;
    }
    else if (c == '\b')
    {
        if (vt->cursor_x == 0)
            return false;

        vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
        vt->cursor_x--;
    }
    else if (c == '\x7f')
    {
        /* Delete char */
        if (vt->cursor_x == 0)
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

    if (vt->cursor_x == vt->columns)
    {
        /* Forced newline */
        vt->cursor_x = 0;
        vt->cursor_y++;
    }

    if (vt->cursor_y == vt->bottom)
    {
        if (vt->cursor_y <= vt->bottom && vt->cursor_y >= vt->top)
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

    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            struct color color;
            unsigned char f = font->cursor_bitmap[i];

            if (f & font->mask[j])
                continue;
            else
                color = fg;

            uint32_t c = unpack_rgba(color, fb);
            volatile uint32_t *b = (volatile uint32_t *) ((uint32_t *) buffer + j);

            /* If the bpp is 32 bits, we can just blit it out */
            if (fb->bpp == 32)
                *b = c;
            else
            {
                volatile unsigned char *buf = (volatile unsigned char *) (buffer + j);
                int bytes = fb->bpp / 8;
                for (int k = 0; k < bytes; k++)
                {
                    buf[k] = c;
                    c >>= 8;
                }
            }
        }

        buffer = (volatile char *) (((char *) buffer) + fb->pitch);
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
    int base_row = 0;
    for (unsigned int i = 0; i < vterm->bitmap_size; i++, base_row += LONG_SIZE_BITS)
    {
        while (vterm->dirty_row_bitmap[i] != 0)
        {
            int bit = __builtin_ffsl(vterm->dirty_row_bitmap[i]) - 1;
            int row = bit + base_row;
            vterm->dirty_row_bitmap[i] &= ~(1UL << bit);

            for (unsigned int j = 0; j < vterm->columns; j++)
            {
                struct console_cell *cell = &vterm->cells[row * vterm->columns + j];

                if (vterm_is_dirty(cell))
                {
                    draw_char(cell->codepoint, j * f->width, row * f->height, vterm->fb, cell->fg,
                              cell->bg);
                    vterm_clear_dirty(cell);
                }
            }
        }
    }
}

void platform_serial_write(const char *s, size_t size);

void vterm_flush(struct vterm *vterm)
{
    if (vterm->flush_all)
    {
        do_vterm_flush_all(vterm);
        vterm->flush_all = false;
        return;
    }

    if (vterm->multithread_enabled)
        vterm_send_message(vterm, VTERM_MESSAGE_FLUSH, NULL);
    else
        do_vterm_flush(vterm);
}

void vterm_fill_screen(struct vterm *vterm, uint32_t character, struct color fg, struct color bg)
{
    for (unsigned int i = 0; i < vterm->columns; i++)
    {
        for (unsigned int j = 0; j < vterm->rows; j++)
        {
            struct console_cell *cell = &vterm->cells[i * vterm->rows + j];
            vterm_dirty_cell(i, j, vterm);
            cell->codepoint = character;
            cell->bg = bg;
            cell->fg = fg;
        }
    }
}

struct vterm primary_vterm = {};

static void fb_fill_color(uint32_t color, struct framebuffer *frameb)
{
    volatile uint32_t *fb = (volatile uint32_t *) frameb->framebuffer;

    for (size_t i = 0; i < frameb->height; i++)
    {
        for (size_t j = 0; j < frameb->width; j++)
            fb[j] = color;
        fb = (volatile uint32_t *) ((char *) fb + frameb->pitch);
    }
}

void vterm_set_fgcolor(struct color c, struct vterm *vt)
{
    vt->fg = c;
}

int isdigit(int c)
{
    return c - '0' < 10;
}

void vterm_ansi_adjust_cursor(char code, unsigned long relative, struct vterm *vt)
{
    vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
    if (relative == 0 || relative == 1)
        relative = 1;

    switch (code)
    {
        case ANSI_CURSOR_UP: {
            unsigned int cy = vt->cursor_y;
            unsigned int result = cy - relative;

            /* Clamp the result */
            if (cy < result)
            {
                vt->cursor_y = 0;
            }
            else
                vt->cursor_y = result;
            break;
        }
        case ANSI_CURSOR_DOWN:
        case CSI_VPR: {
            unsigned int cy = vt->cursor_y;
            unsigned int result = cy + relative;

            if (result > vt->rows - 1)
                result = vt->rows - 1;
            vt->cursor_y = result;
            break;
        }
        case ANSI_CURSOR_FORWARD: {
            unsigned int cx = vt->cursor_x;
            unsigned int result = cx + relative;

            if (result > vt->columns - 1)
                result = vt->columns - 1;
            vt->cursor_x = result;
            break;
        }
        case ANSI_CURSOR_BACK: {
            unsigned int cx = vt->cursor_x;
            unsigned int result = cx - relative;

            /* Clamp the result */
            if (cx < result)
            {
                vt->cursor_x = 0;
            }
            else
                vt->cursor_x = result;
            break;
        }
    }
}

void vterm_cursor_set_line(unsigned long line, struct vterm *vt)
{
    vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);

    line--;

    if (line >= vt->rows)
        line = vt->rows - 1;

    vt->cursor_y = line;
}

void vterm_ansi_do_cup(unsigned long x, unsigned long y, struct vterm *vt)
{
    vterm_dirty_cell(vt->cursor_x, vt->cursor_y, vt);
    /* Transform x and y into 0-based values */

    x--;
    y--;

    if (x > vt->columns - 1)
        x = vt->columns - 1;
    if (y > vt->rows - 1)
        y = vt->rows - 1;

    vt->cursor_x = x;
    vt->cursor_y = y;
}

void vterm_blink_thread(void *ctx)
{
    struct vterm *vt = (vterm *) ctx;

    while (true)
    {
        struct font *f = get_font_data();
        mutex_lock(&vt->vt_lock);

        if (vt->blink_die)
        {
            mutex_unlock(&vt->vt_lock);
            sched_sleep_until_wake();
            mutex_lock(&vt->vt_lock);
        }

        struct color c = vt->fg;
        if (vt->blink_status == true)
        {
            vt->blink_status = false;
            c = vt->bg;
        }
        else
            vt->blink_status = true;

        draw_cursor(vt->cursor_x * f->width, vt->cursor_y * f->height, vt->fb, c);

        mutex_unlock(&vt->vt_lock);
        sched_sleep_ms(500);
    }
}

void vterm_ansi_do_sgr(unsigned long n, struct vterm *vt)
{
    switch (n)
    {
        case ANSI_SGR_RESET: {
            vt->bg = default_bg;
            vt->fg = default_fg;
            vt->reversed = false;
            break;
        }

        case ANSI_SGR_REVERSE: {
            if (vt->reversed)
                return;
            struct color temp = vt->bg;
            vt->bg = vt->fg;
            vt->fg = temp;
            vt->reversed = true;
            break;
        }

        case ANSI_SGR_NOREVERSE: {
            if (!vt->reversed)
                return;
            struct color temp = vt->bg;
            vt->bg = vt->fg;
            vt->fg = temp;
            vt->reversed = false;
            break;
        }

        case ANSI_SGR_DEFAULTBG: {
            vt->bg = default_bg;
            break;
        }

        case ANSI_SGR_DEFAULTFG: {
            vt->fg = default_fg;
            break;
        }

        case ANSI_SGR_SLOWBLINK:
        case ANSI_SGR_RAPIDBLINK: {
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

        case ANSI_SGR_BLINKOFF: {
            if (vt->blink_thread)
                thread_destroy(vt->blink_thread);
            break;
        }

        default: {
            if (n >= ANSI_SGR_SETBGMIN && n <= ANSI_SGR_SETBGMAX)
            {
                int index = n - ANSI_SGR_SETBGMIN;
                vt->bg = color_table[index];
            }
            else if (n >= ANSI_SGR_SETFGMIN && n <= ANSI_SGR_SETFGMAX)
            {
                int index = n - ANSI_SGR_SETFGMIN;
                vt->fg = color_table[index];
            }
        }
    }
}

void vterm_ansi_erase_in_line(unsigned long n, struct vterm *vt)
{
    switch (n)
    {
        /* Clear from cursor to end */
        case 0: {
            vterm_clear_range(vt, vt->cursor_x, vt->cursor_y, vt->columns, vt->cursor_y);
            break;
        }

        /* Clear from cursor to beginning */
        case 1: {
            vterm_clear_range(vt, 0, vt->cursor_y, vt->cursor_x + 1, vt->cursor_y);
            break;
        }

        /* Clear entire line */
        case 2: {
            vterm_clear_range(vt, 0, vt->cursor_y, 0, vt->cursor_y + 1);
            break;
        }
    }
}

void vterm_ansi_erase_in_display(unsigned long n, struct vterm *vt)
{
    switch (n)
    {
        /* Cursor to end of display */
        case 0: {
            vterm_clear_range(vt, vt->cursor_x, vt->cursor_y, 0, vt->rows);
            break;
        }

        /* Cursor to start of display */
        case 1: {
            vterm_clear_range(vt, 0, 0, vt->cursor_x + 1, vt->cursor_y);
            break;
        }

        /* Whole screen */
        case 2:
        case 3: {
            vterm_fill_screen(vt, ' ', vt->fg, vt->bg);
            break;
        }
    }

    vterm_flush(vt);
}

void vterm_csi_delete_chars(unsigned long chars, struct vterm *vt)
{
    unsigned int x = vt->cursor_x;

    if (chars > vt->columns - x)
        chars = vt->columns - x;

    memcpy(&vt->cells[vt->cursor_y * vt->columns + x],
           &vt->cells[vt->cursor_y * vt->columns + x + chars],
           sizeof(console_cell) * (vt->columns - x - chars));

    for (unsigned int i = 0; i < vt->columns; i++)
    {
        struct console_cell *c = &vt->cells[vt->cursor_y * vt->columns + i];

        if (i >= vt->columns - chars)
        {
            c->codepoint = ' ';
            c->fg = vt->fg;
            c->bg = vt->bg;
        }

        vterm_dirty_cell(i, vt->cursor_y, vt);
    }
}

void vterm::insert_blank(unsigned long nr)
{
    auto x = cursor_x;
    auto to_blank = cul::min((unsigned int) nr, columns - x);
    memmove(&cells[cursor_y * columns + x + to_blank], &cells[cursor_y * columns + x],
            sizeof(console_cell) * (columns - nr - x));

    for (unsigned int i = x; i < columns; i++)
    {
        auto &cell = cells[cursor_y * columns + i];
        if (i < x + to_blank)
        {
            cell.codepoint = ' ';
            cell.fg = fg;
            cell.bg = bg;
        }

        vterm_dirty_cell(i, cursor_y, this);
    }
}

void vterm::do_dec_command(char c)
{
    switch (c)
    {
        case DEC_DECALN:
            vterm_fill_screen(this, 'E', fg, bg);
    }
}

void vterm::do_ri()
{
    vterm_dirty_cell(cursor_x, cursor_y, this);
    if (cursor_y == top)
    {
        vterm_scroll_down(fb, this);
        vterm_flush_all(this);
    }
    else if (cursor_y)
        cursor_y--;
}

void vterm::do_nl()
{
    vterm_dirty_cell(cursor_x, cursor_y, this);
    cursor_y++;
    if (cursor_y == bottom)
    {
        if (cursor_y <= bottom && cursor_y >= top)
        {
            vterm_scroll(fb, this);
            vterm_flush_all(this);
        }
        cursor_y--;
    }
}

void vterm::do_cr()
{
    vterm_dirty_cell(cursor_x, cursor_y, this);
    cursor_x = 0;
}

void vterm::do_generic_escape(char escape)
{
    switch (escape)
    {
        case 'D': {
            /* 'D' = NL */
            do_nl();
            break;
        }
        case 'M': {
            /* 'M' == C1 RI (0x8d), move cursor up and scroll if needed */
            do_ri();
            break;
        }
        case 'E': {
            /* 'E' = CRNL */
            do_cr();
            do_nl();
            break;
        }

        case ESC_SAVECUR: {
            saved_x = cursor_x;
            saved_y = cursor_y;
            break;
        }

        case ESC_RESTORECUR: {
            cursor_x = saved_x;
            cursor_y = saved_y;
            break;
        }

        case ')': {
            /* TODO: Do properly. This is quite awkward to do because parsing ESC ( 0 isn't trivial
             * since all other ESC's don't take any sort of arguments. */
            gx[1] = Gx_GRAPH;
            break;
        }

        default: {
            // pr_info("vterm: Unhandled ESC %c\n", escape);
            break;
        }
    }
}

void vterm::do_device_attributes(unsigned long nr)
{
    if (nr != 0)
        return; // Unrecognized command

    // c with nr = 5 is a "who are you" command
    // Return Base VT100, no options in stdin
    tty_send_response(tty, (char *) "\x1b[?1;0c");
}

void vterm::do_device_status_report(unsigned long nr)
{
    switch (nr)
    {
        // Command from host – Please report status (using a DSR control sequence)
        case 5: {
            // Only two responses possible
            // Ps = 0 -> terminal is fine
            // Ps = 3 -> malfunction
            // As we are a virtual terminal I don't see a usecase for malfunction here.
            tty_send_response(tty, (char *) "\x1b[0n");
            break;
        }
        // Command from host - Please report active position (using a CPR control sequence)
        case 6: {
            char buffer[20];
            snprintf(buffer, 20, "\x1b[%u;%uR", cursor_y + 1, cursor_x + 1);
            tty_send_response(tty, buffer);
            break;
        }
    }
}

void vterm::reset_escape_status()
{
    in_escape = false;

    if (in_csi || in_dec)
    {
        for (auto &n : csi_data.args)
            n = 0;

        csi_data.nr_args = 0;
        csi_data.escape_character = '\0';
        csi_data.in_arg = false;
        csi_data.dec_private = false;
    }

    in_dec = false;
    in_csi = false;

    seq_finished = false;
}

void vterm::process_dec_char(char c)
{
    // DEC commands have the format
    // ESC #<n> where n is a digit
    csi_data.escape_character = c;

    seq_finished = true;
}

void vterm::process_csi_char(char c)
{
    if (isdigit(c))
    {
        unsigned int digit = c - '0';
        // This is surely part of an argument, or the beginning of one
        if (csi_data.in_arg)
        {
            auto &arg = csi_data.args[csi_data.nr_args - 1];
            // We add space for another digit in the variable and add it in
            // TODO: Can an overflow here be an attack vector?
            arg *= 10;
            arg += digit;
        }
        else
        {
            // Consume the character but don't add it, as we've hit the hard limit
            if (csi_data.nr_args == MAX_ARGS - 1)
                return;

            csi_data.nr_args++;
            csi_data.args[csi_data.nr_args - 1] = digit;
            csi_data.in_arg = true;
        }
    }
    else if (c == ';')
    {
        if (!csi_data.in_arg)
        {
            // Consume the character but don't add it, as we've hit the hard limit
            if (csi_data.nr_args == MAX_ARGS - 1)
                return;
            // This is the codepath that catches stuff like [;2 where the
            // first arg should be 0 and the second 2
            csi_data.args[csi_data.nr_args] = 0;
            csi_data.nr_args++;
        }

        csi_data.in_arg = false;
    }
    else if (c == '?')
    {
        csi_data.dec_private = true;
    }
    else
    {
        csi_data.escape_character = c;
        seq_finished = true;
    }
}

void vterm::process_escape_char(char c)
{
    switch (c)
    {
        case ANSI_ESCAPE_CODE: {
            if (in_escape)
            {
                // platform_serial_write("Reset", strlen("Reset"));
                reset_escape_status();
            }

            // platform_serial_write("InEsc", strlen("InEsc"));

            in_escape = true;
            break;
        }

        case ANSI_CSI: {
            // We should have only gotten here if we got an escape character before
            // so we don't need to check for in_escape
            in_csi = true;
            break;
        }

        case DEC_CSI: {
            in_dec = true;
            break;
        }

        default: {
            if (in_csi)
                process_csi_char(c);
            else if (in_dec)
                process_dec_char(c);
            else
            {
                csi_data.escape_character = c;
                seq_finished = true;
            }

            break;
        }
    }
}

template <typename T>
static inline T clamp(T val, T min, T max)
{
    return cul::min(cul::max(val, min), max);
}

void vterm::do_csi_command(char escape)
{
    if (csi_data.dec_private)
        return;

    auto &args = csi_data.args;
    switch (escape)
    {
        case ANSI_CURSOR_UP:
        case ANSI_CURSOR_DOWN:
        case ANSI_CURSOR_FORWARD:
        case ANSI_CURSOR_BACK:
        case CSI_VPR: {
            vterm_ansi_adjust_cursor(escape, csi_data.args[0], this);
            break;
        }

        case ANSI_CURSOR_PREVIOUS: {
            /* Do a ANSI_CURSOR_UP and set x to 0 (beginning of line) */
            vterm_ansi_adjust_cursor(ANSI_CURSOR_UP, args[0], this);
            cursor_x = 0;
            break;
        }

        case ANSI_CURSOR_NEXT_LINE: {
            /* Do a ANSI_CURSOR_DOWN and set x to 0 (beginning of line) */
            vterm_ansi_adjust_cursor(ANSI_CURSOR_DOWN, args[0], this);
            cursor_x = 0;
            break;
        }

        case ANSI_CURSOR_HORIZONTAL_ABS: {
            if (args[0] > columns - 1)
                args[0] = columns - 1;
            cursor_x = args[0] - 1;
            break;
        }

        case ANSI_CURSOR_POS:
        case ANSI_HVP: {
            if (args[0] == 0)
                args[0] = 1;
            if (args[1] == 0)
                args[1] = 1;

            vterm_ansi_do_cup(args[1], args[0], this);
            break;
        }

        case ANSI_SCROLL_UP: {
            for (unsigned long i = 0; i < args[0]; i++)
                vterm_scroll(fb, this);
            break;
        }

        case ANSI_SCROLL_DOWN: {
            for (unsigned long i = 0; i < args[0]; i++)
                vterm_scroll_down(fb, this);
            vterm_flush_all(this);
            break;
        }

        case ANSI_SGR: {
            // If no args are given, CSI m = CSI 0 m (reset)
            if (!csi_data.nr_args)
            {
                args[0] = 0;
                csi_data.nr_args = 1;
            }

            for (size_t i = 0; i < csi_data.nr_args; i++)
                vterm_ansi_do_sgr(args[i], this);
            break;
        }

        case ANSI_ERASE_IN_LINE: {
            vterm_ansi_erase_in_line(args[0], this);
            break;
        }

        case ANSI_ERASE_IN_DISPLAY: {
            vterm_ansi_erase_in_display(args[0], this);
            break;
        }

        case ANSI_SAVE_CURSOR: {
            saved_x = cursor_x;
            saved_y = cursor_y;
            break;
        }

        case ANSI_RESTORE_CURSOR: {
            cursor_x = saved_x;
            cursor_y = saved_y;
            break;
        }

        case CSI_DELETE_CHARS: {
            if (args[0] == 0)
                args[0] = 1;
            vterm_csi_delete_chars(args[0], this);
            break;
        }

        case CSI_INSERT_BLANK: {
            if (args[0] == 0)
                args[0] = 1;

            insert_blank(args[0]);
            break;
        }

        case CSI_DEVICE_ATTRIBUTES: {
            do_device_attributes(args[0]);
            break;
        }

        case CSI_DEVICE_STATUS_REPORT: {
            do_device_status_report(args[0]);
            break;
        }

        case CSI_VPA: {
            if (!args[0])
                args[0] = 1;
            vterm_cursor_set_line(args[0], this);
            break;
        }

        case CSI_INSERT_LINE: {
            if (args[0] == 0)
                args[0] = 1;

            insert_lines(args[0]);
            break;
        }

        case CSI_DELETE_LINE: {
            if (args[0] == 0)
                args[0] = 1;

            delete_lines(args[0]);
            break;
        }

        case CSI_REP: {
            if (args[0] == 0)
                args[0] = 1;
            repeat_last(args[0]);
            break;
        }

        case CSI_SET_SCROLLING_REGION: {
            if (args[0] == 0)
                args[0] = 1;
            if (args[1] == 0)
                args[1] = rows;
            /* Check that bottom > top and that bottom <= rows */
            if (args[1] > args[0] && args[1] <= rows)
            {
                top = args[0] - 1;
                bottom = args[1];
                vterm_dirty_cell(cursor_x, cursor_y, this);
                cursor_x = 0;
                cursor_y = 0;
            }
            break;
        }

        case CSI_ERASE_CHARS: {
            unsigned long nr = clamp<unsigned long>(args[0], 1, columns - cursor_x);
            vterm_clear_range(this, cursor_x, cursor_y, cursor_x + nr, cursor_y);
            break;
        }

        default: {
            // pr_info("vt: Unimplemented escape %c\n", escape);
            break;
        }
    }
}

void vterm::repeat_last(unsigned long nr)
{
    char c = (char) last_char;
    if (!isprint(c))
        return;

    for (unsigned long i = 0; i < nr; i++)
        vterm_putc(c, this);
}

void vterm::insert_lines(unsigned long nr)
{
    auto possible_lines_to_insert = rows - cursor_y - 1;

    if (nr > possible_lines_to_insert)
        nr = possible_lines_to_insert;

    __vterm_scroll_down(fb, this, nr, cursor_y, bottom);
    vterm_flush_all(this);
}

void vterm::delete_lines(unsigned long nr)
{
    nr = clamp<unsigned long>(nr, 1, rows - cursor_y);
    __vterm_scroll(fb, this, nr, cursor_y, bottom);
}

size_t vterm::do_escape(const char *buffer, size_t len)
{
    size_t processed = 0;
    for (size_t i = 0; i < len; i++)
    {
        process_escape_char(buffer[i]);
        processed++;

        if (seq_finished)
            break;
    }

    if (!seq_finished)
        return processed;

    char escape = csi_data.escape_character;

#if 0
    if (in_csi)
        pr_info("Seq: %c nargs %lu args {%lu, %lu}\n", escape, csi_data.nr_args, csi_data.args[0],
                csi_data.args[1]);
    else if (in_dec)
        pr_info("doing DEC escape %c\n", escape);
    else
        pr_info("doing generic escape %c\n", escape);
#endif

    if (in_dec)
        do_dec_command(escape);
    else if (in_csi)
        do_csi_command(escape);
    else
        do_generic_escape(escape);

    reset_escape_status();
    return processed;
}

ssize_t vterm_write_tty(const void *buffer, size_t size, struct tty *tty)
{
    // platform_serial_write((const char *) buffer, size);
    struct vterm *vt = (vterm *) tty->priv;

    mutex_lock(&vt->vt_lock);
    size_t i = 0;
    const char *data = (const char *) buffer;

    for (; i < size; i++)
    {
        if (data[i] == '\0')
            continue;
        /* Parse ANSI terminal escape codes */
        if (data[i] == ANSI_ESCAPE_CODE || vt->in_escape)
            /* Note the -1 because of the i++ in the for loop */
            i += vt->do_escape(&data[i], size - i) - 1;
        else
        {
            size_t codepoint_length = 0;
            utf32_t codepoint = utf8to32((utf8_t *) data + i, size - i, &codepoint_length);

            /* TODO: Detect surrogates, overlong sequences. The code I wrote before
             * has some weird casting and returns.
             */
            if (codepoint == UTF_INVALID_CODEPOINT)
            {
                codepoint = '?';
                codepoint_length = 1;
            }
#if 0
            char x[9];
            snprintf(x, 9, "%x\n", codepoint);
            platform_serial_write(x, strlen(x));
#endif
            // platform_serial_write(data + i, 1);
            vterm_putc(codepoint, vt);

            /* We sub a 1 because we're incrementing on the for loop */
            i += codepoint_length - 1;
        }
    }

    vterm_flush(vt);
    update_cursor(vt);

    mutex_unlock(&vt->vt_lock);
    return i;
}

unsigned int vterm_ioctl_tty(int request, void *argp, struct tty *tty)
{
    struct vterm *vt = (vterm *) tty->priv;

    switch (request)
    {
        case TIOCGWINSZ: {
            struct winsize *win = (winsize *) argp;
            struct winsize kwin = {};
            kwin.ws_row = vt->rows;
            kwin.ws_col = vt->columns;
            kwin.ws_xpixel = vt->fb->width;
            kwin.ws_ypixel = vt->fb->height;
            if (copy_to_user(win, &kwin, sizeof(struct winsize)) < 0)
                return -EFAULT;
            return 0;
        }
        default:
            return -EINVAL;
    }
}

void vterm_init(struct tty *tty)
{
    struct vterm *vt = (vterm *) tty->priv;

    mutex_init(&vt->vt_lock);
    mutex_init(&vt->condvar_mutex);

    tty->is_vterm = true;
    struct framebuffer *fb = get_primary_framebuffer();
    struct font *font = get_font_data();
    vt->columns = fb->width / font->width;
    vt->rows = fb->height / font->height;
    vt->top = 0;
    vt->bottom = vt->rows;
    vt->fb = fb;
    vt->cells =
        (console_cell *) vmalloc(vm_size_to_pages(vt->columns * vt->rows * sizeof(*vt->cells)),
                                 VM_TYPE_REGULAR, VM_READ | VM_WRITE, GFP_KERNEL);
    assert(vt->cells != NULL);

    vt->fg = default_fg;
    vt->bg = default_bg;

    int bitmap_size =
        vt->rows / (sizeof(unsigned long) * 8) + ((vt->rows % (sizeof(unsigned long) * 8)) != 0);
    vt->dirty_row_bitmap =
        (unsigned long *) kcalloc(bitmap_size, sizeof(unsigned long), GFP_KERNEL);
    CHECK(vt->dirty_row_bitmap);
    vt->bitmap_size = bitmap_size;

    vterm_fill_screen(vt, ' ', vt->fg, vt->bg);

    vterm_flush(vt);

    update_cursor(vt);

    tty->read = NULL;
    tty->write = vterm_write_tty;
    tty->ioctl = vterm_ioctl_tty;

    vt->tty = tty;
}

static int vterm_write_con(const char *buffer, size_t size, unsigned int flags,
                           struct console *con) NO_THREAD_SAFETY_ANALYSIS
{
    struct vterm *vt = (struct vterm *) con->priv;
    bool has_lock = true;

    if (flags & (CONSOLE_WRITE_ATOMIC | CONSOLE_WRITE_PANIC))
    {
        if (!mutex_trylock(&vt->vt_lock))
        {
            has_lock = false;
            if (!(flags & CONSOLE_WRITE_PANIC))
                return -EAGAIN;
        }

        if (flags & CONSOLE_WRITE_PANIC)
            vt->in_escape = false;
    }
    else
        mutex_lock(&vt->vt_lock);

    size_t i = 0;
    const char *data = (const char *) buffer;
    bool did_scroll = false;

    for (; i < size; i++)
    {
        if (data[i] == '\0')
            continue;
        /* Parse ANSI terminal escape codes */
        if (data[i] == ANSI_ESCAPE_CODE || vt->in_escape)
            /* Note the -1 because of the i++ in the for loop */
            i += vt->do_escape(&data[i], size - i) - 1;
        else
        {
            size_t codepoint_length = 0;
            utf32_t codepoint = utf8to32((utf8_t *) data + i, size - i, &codepoint_length);

            /* TODO: Detect surrogates, overlong sequences. The code I wrote before
             * has some weird casting and returns.
             */
            if (codepoint == UTF_INVALID_CODEPOINT)
            {
                codepoint = '?';
                codepoint_length = 1;
            }

            if (codepoint == '\n')
            {
                /* If LF, do CRLF */
                vterm_putc('\r', vt);
            }

            if (vterm_putc(codepoint, vt))
                did_scroll = true;

            /* We sub a 1 because we're incrementing on the for loop */
            i += codepoint_length - 1;
        }
    }

    if (!did_scroll)
        vterm_flush(vt);
    else
        vterm_flush_all(vt);
    update_cursor(vt);

    if (has_lock)
        mutex_unlock(&vt->vt_lock);

    return 0;
}

const struct console_ops vterm_con_ops = {
    .write = vterm_write_con,
};

void vterm_do_init(void)
{
    struct framebuffer *fb = get_primary_framebuffer();
    if (fb)
    {
        tty_init(&primary_vterm, vterm_init, 0);
        struct console *con = (struct console *) kmalloc(sizeof(struct console), GFP_KERNEL);
        CHECK(con != nullptr);
        console_init(con, "vterm", &vterm_con_ops);
        con->priv = &primary_vterm;
        con->flags |= CONSOLE_FLAG_VTERM;
        con_register(con);
    }
}

struct vterm *get_current_vt(void)
{
    return &primary_vterm;
}

int vterm_receive_input(char *c)
{
    struct vterm *vt = get_current_vt();
    if (!vt)
        return -1;

    tty_received_characters(vt->tty, c);

    return 0;
}

struct key_action
{
    keycode_t key;
    const char *action;
    const char *shift_action;
    const char *ctrl_action;
    const char *alt_action;
    uint8_t flags;
};

struct key_action key_actions[] = {
    {KEYMAP_KEY_A, "a", "A", "\01"},
    {KEYMAP_KEY_B, "b", "B", "\02"},
    {KEYMAP_KEY_C, "c", "C", "\03"},
    {KEYMAP_KEY_D, "d", "D", "\04"},
    {KEYMAP_KEY_E, "e", "E", "\05"},
    {KEYMAP_KEY_F, "f", "F", "\06"},
    {KEYMAP_KEY_G, "g", "G", "\07"},
    {KEYMAP_KEY_H, "h", "H", "\010"},
    {KEYMAP_KEY_I, "i", "I", "\011"},
    {KEYMAP_KEY_J, "j", "J", "\012"},
    {KEYMAP_KEY_K, "k", "K", "\013"},
    {KEYMAP_KEY_L, "l", "L", "\014"},
    {KEYMAP_KEY_M, "m", "M", "\015"},
    {KEYMAP_KEY_N, "n", "N", "\016"},
    {KEYMAP_KEY_O, "o", "O", "\017"},
    {KEYMAP_KEY_P, "p", "P", "\020"},
    {KEYMAP_KEY_Q, "q", "Q", "\021"},
    {KEYMAP_KEY_R, "r", "R", "\022"},
    {KEYMAP_KEY_S, "s", "S", "\023"},
    {KEYMAP_KEY_T, "t", "T", "\024"},
    {KEYMAP_KEY_U, "u", "U", "\025"},
    {KEYMAP_KEY_V, "v", "V", "\026"},
    {KEYMAP_KEY_W, "w", "W", "\027"},
    {KEYMAP_KEY_X, "x", "X", "\030"},
    {KEYMAP_KEY_Y, "y", "Y", "\031"},
    {KEYMAP_KEY_Z, "z", "Z", "\032"},
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
    {KEYMAP_KEY_ENTER, "\r"},
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
    {KEYMAP_KEY_SPACE, " ", " "},
    {KEYMAP_KEY_ARROW_LEFT, "\033[D", NULL, "\033[1;5D"},
    {KEYMAP_KEY_ARROW_UP, "\033[A", NULL, "\033[1;5A"},
    {KEYMAP_KEY_ARROW_DOWN, "\033[B", NULL, "\033[1;5B"},
    {KEYMAP_KEY_ARROW_RIGHT, "\033[C", NULL, "\033[1;5C"},
    {KEYMAP_KEY_ESC, "\033"},
};

struct key_action pt_pt_key_actions[] = {
    {KEYMAP_KEY_A, "a", "A", "\01"},
    {KEYMAP_KEY_B, "b", "B", "\02"},
    {KEYMAP_KEY_C, "c", "C", "\03"},
    {KEYMAP_KEY_D, "d", "D", "\04"},
    {KEYMAP_KEY_E, "e", "E", "\05"},
    {KEYMAP_KEY_F, "f", "F", "\06"},
    {KEYMAP_KEY_G, "g", "G", "\07"},
    {KEYMAP_KEY_H, "h", "H", "\010"},
    {KEYMAP_KEY_I, "i", "I", "\011"},
    {KEYMAP_KEY_J, "j", "J", "\012"},
    {KEYMAP_KEY_K, "k", "K", "\013"},
    {KEYMAP_KEY_L, "l", "L", "\014"},
    {KEYMAP_KEY_M, "m", "M", "\015"},
    {KEYMAP_KEY_N, "n", "N", "\016"},
    {KEYMAP_KEY_O, "o", "O", "\017"},
    {KEYMAP_KEY_P, "p", "P", "\020"},
    {KEYMAP_KEY_Q, "q", "Q", "\021"},
    {KEYMAP_KEY_R, "r", "R", "\022"},
    {KEYMAP_KEY_S, "s", "S", "\023"},
    {KEYMAP_KEY_T, "t", "T", "\024"},
    {KEYMAP_KEY_U, "u", "U", "\025"},
    {KEYMAP_KEY_V, "v", "V", "\026"},
    {KEYMAP_KEY_W, "w", "W", "\027"},
    {KEYMAP_KEY_X, "x", "X", "\030"},
    {KEYMAP_KEY_Y, "y", "Y", "\031"},
    {KEYMAP_KEY_Z, "z", "Z", "\032"},
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
    {KEYMAP_KEY_ENTER, "\r"},
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
    {KEYMAP_102ND, "<", ">"},
    {KEYMAP_KEY_ARROW_LEFT, "\033[D", NULL, "\033[1;5D"},
    {KEYMAP_KEY_ARROW_UP, "\033[A", NULL, "\033[1;5A"},
    {KEYMAP_KEY_ARROW_DOWN, "\033[B", NULL, "\033[1;5B"},
    {KEYMAP_KEY_ARROW_RIGHT, "\033[C", NULL, "\033[1;5C"},
    {KEYMAP_KEY_ESC, "\033"},
};

const size_t nr_actions = sizeof(key_actions) / sizeof(key_actions[0]);

void __vterm_receive_input(void *p)
{
    char *s = (char *) p;
    vterm_receive_input(s);
}

void sched_dump_threads(void);

static bool is_numpad_code(keycode_t code)
{
    switch (code)
    {
        /* Ew... Depends on the KEYPAD's enum layout */
        case KEYMAP_KEY_KEYPAD_7 ... KEYMAP_KEY_KEYPAD_PLUS:
            return true;
        default:
            return false;
    }
}

static const char *numpad_replacement(keycode_t code, const char *str)
{
    switch (code)
    {
        case KEYMAP_KEY_KEYPAD_7:
            return "\033[H";
        case KEYMAP_KEY_KEYPAD_8:
            return "\033[A";
        case KEYMAP_KEY_KEYPAD_9:
            return "\033[5~";
        case KEYMAP_KEY_KEYPAD_4:
            return "\033[D";
        case KEYMAP_KEY_KEYPAD_5:
            return "\033[E";
        case KEYMAP_KEY_KEYPAD_6:
            return "\033[C";
        case KEYMAP_KEY_KEYPAD_1:
            return "\033[F";
        case KEYMAP_KEY_KEYPAD_2:
            return "\033[B";
        case KEYMAP_KEY_KEYPAD_3:
            return "\033[6~";
        default:
            return str;
    }
}

int vterm_handle_key(struct vterm *vt, struct input_device *dev, struct input_event *ev)
{
    /* We have no interest in release events */
    if (!(ev->flags & INPUT_EVENT_FLAG_PRESSED))
        return 0;
#ifdef CONFIG_SCHED_DUMP_THREADS_MAGIC
    /* Don't have this enabled by default */
    if (ev->code == KEYMAP_KEY_KEYPAD_NUMLCK)
        sched_dump_threads();
#endif

    if (ev->code == KEYMAP_KEY_KEYPAD_NUMLCK)
        vt->numlck = !vt->numlck;

    struct key_action *acts = pt_pt_key_actions;
    struct key_action *desired_action = NULL;

    for (size_t i = 0; i <= nr_actions; i++)
    {
        if (acts[i].key == ev->code)
        {
            desired_action = &acts[i];
            break;
        }
    }

    /* Not mapped */
    if (!desired_action)
    {
        return 0;
    }

    const char *action_string = NULL;

    if (unlikely(dev->state.shift_pressed || dev->state.caps_enabled))
    {
        action_string = desired_action->shift_action;
    }
    else if (unlikely(dev->state.ctrl_pressed))
    {
        action_string = desired_action->ctrl_action;
    }
    else if (unlikely(dev->state.alt_pressed))
    {
        action_string = desired_action->alt_action;
    }
    else
    {
        action_string = desired_action->action;
    }

    if (!vt->numlck && is_numpad_code(ev->code))
        action_string = numpad_replacement(ev->code, action_string);

    if (likely(action_string))
    {
        struct dpc_work w;
        w.context = (void *) action_string;
        w.funcptr = __vterm_receive_input;
        dpc_schedule_work(&w, DPC_PRIORITY_MEDIUM);
    }

    return 0;
}

int vterm_submit_event(struct input_device *dev, struct input_event *ev)
{
    struct vterm *vt = get_current_vt();
    if (!vt)
        return -1;

    return vterm_handle_key(vt, dev, ev);
}

void vterm_handle_message(struct vterm_message *msg, struct vterm *vt)
{
    switch (msg->message)
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
    while (msg != NULL)
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
    struct vterm *vt = (vterm *) arg;

    mutex_lock(&vt->condvar_mutex);

    while (true)
    {
        condvar_wait(&vt->condvar, &vt->condvar_mutex);
        vterm_handle_messages(vt);
    }
}

void vterm_switch_to_multithread(struct vterm *vt)
{
    vt->render_thread = sched_create_thread(vterm_render_thread, THREAD_KERNEL, vt);

    assert(vt->render_thread != NULL);

    vt->multithread_enabled = false;

    vt->render_thread->priority = SCHED_PRIO_NORMAL;

    sched_start_thread(vt->render_thread);
}

void vt_init_blink(void)
{
    struct vterm *vt = &primary_vterm;
    if (!vt->fb)
        return;
    if (!vt->blink_thread)
    {
        vt->blink_status = false;
        vt->blink_thread = sched_create_thread(vterm_blink_thread, THREAD_KERNEL, vt);
        if (vt->blink_thread)
            sched_start_thread(vt->blink_thread);
    }

    vterm_switch_to_multithread(vt);
}

INIT_LEVEL_CORE_AFTER_SCHED_ENTRY(vt_init_blink);

void vterm_panic(void)
{
    primary_vterm.multithread_enabled = false;

    if (primary_vterm.tty)
        primary_vterm.tty->lock.counter = 0;
    primary_vterm.vt_lock.counter = 0;
}

void vterm_release_video(void *vt_)
{
    struct vterm *vt = (vterm *) vt_;
    mutex_lock(&vt->vt_lock);

    vt->blink_die = true;
    vt->blink_status = true;

    struct font *f = get_font_data();
    draw_cursor(vt->cursor_x * f->width, vt->cursor_y * f->height, vt->fb, vt->fg);

    vterm_send_message(vt, VTERM_MESSAGE_DIE, NULL);

    /* Wait 10ms for the render thread to stop */
    sched_sleep_ms(10);

    mutex_unlock(&vt->vt_lock);
}

void vterm_get_video(void *vt_)
{
    struct vterm *vt = (vterm *) vt_;
    mutex_lock(&vt->vt_lock);

    vt->blink_die = false;

    thread_wake_up(vt->blink_thread);

    thread_wake_up(vt->render_thread);

    mutex_unlock(&vt->vt_lock);
}
