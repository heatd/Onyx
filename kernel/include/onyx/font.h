/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */

#ifndef _CARBON_FONT_H
#define _CARBON_FONT_H

struct font
{
    unsigned char *font_bitmap;
    unsigned int width;
    unsigned int height;
    unsigned int chars;
    unsigned int *mask;
    unsigned char *cursor_bitmap;
    unsigned int (*utf2char)(unsigned int codepoint);
};

struct font *get_font_data(void);

#endif
