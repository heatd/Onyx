/*
 * Copyright (c) 2018 Pedro Falcato
 * This file is part of Carbon, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 */
#include <stddef.h>

#include <onyx/dev.h>
#include <onyx/framebuffer.h>
#include <onyx/init.h>
#include <onyx/vfs.h>
#include <onyx/vm.h>

#include "fbpriv.h"

struct framebuffer *primary_fb = nullptr;

struct framebuffer *get_primary_framebuffer()
{
    return primary_fb;
}

void set_framebuffer(struct framebuffer *fb)
{
    primary_fb = fb;
}

int fbdev_do_fscreeninfo(void *argp)
{
    fb_fix_screeninfo info;
    strcpy(info.id, "bootfb");
    info.accel = FB_ACCEL_NONE;
    info.line_length = primary_fb->pitch;
    info.xpanstep = 0;
    info.ypanstep = 0;
    info.ywrapstep = 0;
    info.visual = FB_VISUAL_TRUECOLOR;
    info.type = FB_TYPE_PACKED_PIXELS;
    info.type_aux = 0;
    info.smem_start = (char *) primary_fb->framebuffer_phys;
    info.smem_len = primary_fb->framebuffer_size;
    info.mmio_start = info.smem_start;
    info.mmio_len = info.smem_len;
    info.reserved[0] = 0;

    return copy_to_user(argp, &info, sizeof(info));
}

int fbdev_do_vscreeninfo(void *argp)
{
    fb_var_screeninfo info;
    info.xres = primary_fb->width;
    info.yres = primary_fb->height;
    info.bits_per_pixel = primary_fb->bpp;
    info.xres_virtual = info.xres;
    info.yres_virtual = info.yres;
    info.yoffset = 0;
    info.xoffset = 0;
    info.pixclock = 25000000 / info.xres * 2000 / info.yres;
    info.left_margin = (info.xres / 8) & 0xf8;
    info.hsync_len = info.left_margin;
    info.red.offset = primary_fb->color.red_shift;
    info.red.length = 8;
    info.green.offset = primary_fb->color.green_shift;
    info.green.length = 8;
    info.blue.offset = primary_fb->color.blue_shift;
    info.blue.length = 8;
    info.transp.offset = primary_fb->color.resv_shift;
    info.transp.length = 8;
    info.red.msb_right = 0;
    info.green.msb_right = 0;
    info.blue.msb_right = 0;
    info.transp.msb_right = 0;
    info.grayscale = 0;
    info.nonstd = 0;
    info.activate = FB_ACTIVATE_NOW;
    info.vsync_len = 10;
    info.upper_margin = 32;
    info.lower_margin = 16;
    info.right_margin = 0;
    info.sync = 0;
    info.accel_flags = 0;
    info.vmode = FB_VMODE_NONINTERLACED;

    return copy_to_user(argp, &info, sizeof(info));
}

unsigned int fbdev_ioctl(int request, void *argp, struct file *file)
{
    switch (request)
    {
        case FBIOGET_FSCREENINFO:
            return fbdev_do_fscreeninfo(argp);
        case FBIOGET_VSCREENINFO:
            return fbdev_do_vscreeninfo(argp);
        case FBIOPUT_VSCREENINFO:
        case FBIOPUTCMAP:
            return 0; // noop
    }

    return -ENOTTY;
}

void *fbdev_mmap(struct vm_area_struct *area, struct file *node)
{
    area->vm_flags |= VM_PFNMAP;
    area->vm_obj = vmo_create(0x1000, nullptr);
    if (!area->vm_obj)
        return NULL;
    vmo_assign_mapping(area->vm_obj, area);
    return __map_pages_to_vaddr(area->vm_mm, (void *) area->vm_start,
                                (void *) primary_fb->framebuffer_phys,
                                area->vm_end - area->vm_start, area->vm_flags);
}

const file_ops fbdev_fops = {.read = nullptr, // TODO
                             .ioctl = fbdev_ioctl,
                             .mmap = fbdev_mmap};

/**
 * @brief Initialize fb0
 *
 */
void fbdev_init()
{
    auto ex = dev_register_chardevs(0, 1, 0, &fbdev_fops, "fb0");

    ex.unwrap()->show(0644);
}

INIT_LEVEL_CORE_KERNEL_ENTRY(fbdev_init);
