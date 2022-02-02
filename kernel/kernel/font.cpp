/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <onyx/font.h>

extern "C" struct font boot_font;

struct font *current_font = &boot_font;

struct font *get_font_data(void)
{
    return current_font;
}
