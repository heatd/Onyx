/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#ifndef _ONYX_VIDEO_EDID_H
#define _ONYX_VIDEO_EDID_H

#include <stdint.h>

struct edid_detailed_timing_desc
{
    uint8_t pixel_clock_khz;
    uint8_t horizontal_active_pixels;
    uint8_t horizontal_blanking_pixels;

} __attribute__((packed));

struct edid_data
{
    uint8_t signature[8];
    uint16_t manufacturer_id;
    uint16_t product_code;
    uint32_t serial_number;
    uint8_t week_of_manufacture;
    uint8_t year_of_manufacture;
    uint8_t edid_version;
    uint8_t edid_revision;
    uint8_t input_params;
    uint8_t hscreen_size;
    uint8_t vscreen_size;
    uint8_t display_gamma;
    uint8_t supported_features;
    uint8_t red_green_lsb;
    uint8_t blue_white_lsb;
    uint8_t red_x_msb;
    uint8_t red_y_msb;
    uint16_t green_xy_msb;
    uint16_t blue_xy_msb;
    uint16_t default_white_xy_msb;
    uint8_t timing_bitmap0;
    uint8_t timing_bitmap1;
    uint8_t timing_bitmap2;

    struct
    {
        uint8_t resolution;
        uint8_t frequency;
    } __attribute__((packed)) standard_timings[8];

    struct
    {
        uint16_t pixel_clock;
        uint8_t horz_active;
        uint8_t horz_blank;
        uint8_t horzactive_blank_msb;
        uint8_t vert_active;
        uint8_t vert_blank;
        uint8_t vert_active_blank_msb;
        uint8_t horz_sync_offset;
        uint8_t horz_sync_pulse;
        uint8_t vert_sync;
        uint8_t sync_msb;
        uint8_t dimension_width;
        uint8_t dimension_height;
        uint8_t dimension_msb;
        uint8_t horz_border;
        uint8_t vert_border;
        uint8_t features;
    } __attribute__((packed)) detailed_timings[4];

    uint8_t num_ext;
    uint8_t checksum;

} __attribute__((packed));

#endif
