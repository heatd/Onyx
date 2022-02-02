/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#include <stddef.h>

#include <onyx/framebuffer.h>

struct framebuffer *primary_fb = NULL;

struct framebuffer *get_primary_framebuffer(void)
{
    return primary_fb;
}

void set_framebuffer(struct framebuffer *fb)
{
    primary_fb = fb;
}