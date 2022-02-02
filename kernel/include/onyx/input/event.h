/*
 * Copyright (c) 2020 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#ifndef _ONYX_INPUT_EVENT_H
#define _ONYX_INPUT_EVENT_H

#include <stdint.h>

#include <onyx/input/keys.h>

enum input_event_type
{
    INPUT_EVENT_TYPE_KEYBOARD = 0
};

#define INPUT_EVENT_FLAG_PRESSED (1 << 0)

struct input_event
{
    enum input_event_type type;
    keycode_t code;
    uint16_t flags;
    /* TODO: Add the missing stuff */
};

#endif
