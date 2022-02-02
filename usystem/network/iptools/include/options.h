/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */
#pragma once

enum class family
{
    inet = 0,
    inet6,
    link,
    all
};

enum class display_mode
{
    normal = 0,
    pretty_json,
    json
};

bool is_family_option_enabled(family fam_);

bool is_color_enabled();

display_mode get_display_mode();
