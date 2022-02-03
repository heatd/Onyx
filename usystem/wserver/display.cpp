/*
 * Copyright (c) 2017 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 */

#include <display.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include <photon/photon.h>

void display_fill_rect(void *_fb, unsigned int x, unsigned int y, unsigned int width,
                       unsigned int height, uint32_t color)
{
    size_t bits_per_row = width * (32 / 8);
    volatile unsigned char *__fb = (volatile unsigned char *) _fb;
    __fb += (y * bits_per_row) + x * (32 / 8);
    volatile uint32_t *fb = (volatile uint32_t *) __fb;

    for (size_t i = 0; i < height; i++)
    {
        for (size_t j = 0; j < width; j++)
            fb[j] = color;
        fb = (volatile uint32_t *) ((char *) fb + bits_per_row);
    }
}

void Display::ReleaseOwnershipOfDisplay()
{
    int fd = open("/dev/tty", O_RDWR);

    if (fd < 0)
        throw std::runtime_error("ReleaseOwnershipOfDisplay: Failed to open tty");

    int st = ioctl(fd, TIOONYXCTL, TIO_ONYX_RELEASE_OWNERSHIP_OF_TTY);

    if (st < 0)
    {
        throw std::runtime_error("ioctl tty failed: " + std::string(strerror(errno)));
    }
}

void Display::GetOwnershipOfDisplay()
{
    return;
    /* TODO: We need to add a way to map ttys to displays in the kernel */
    int fd = open("/dev/tty", O_RDWR);

    if (fd < 0)
        throw std::runtime_error("GetOwnershipOfDisplay: Failed to open tty");

    int st = ioctl(fd, TIOONYXCTL, TIO_ONYX_GET_OWNERSHIP_OF_TTY);

    if (st < 0)
    {
        throw std::runtime_error("ioctl tty failed: " + std::string(strerror(errno)));
    }
}

Display::Display()
{
    // if(photon_initialize() < 0)
    throw std::runtime_error("photon_initialize: Failed to"
                             "initialize");

    // if(photon_get_videomode(&videomode) < 0)
    throw std::runtime_error("photon_get_videomode: Failed to get"
                             "video mode");

    framebuffer_map = std::make_unique<Buffer>(videomode.height, videomode.width, videomode.bpp,
                                               weak_from_this());

    framebuffer_map->map();

    GetOwnershipOfDisplay();
}

Display::~Display()
{
    ReleaseOwnershipOfDisplay();
}

std::shared_ptr<Buffer> Display::create_buffer(unsigned int height, unsigned int width)
{
    auto buf = std::make_shared<Buffer>(height, width, weak_from_this());
    buffer_list.push_back(buf);
    return buf;
}

void Display::swap()
{
    // if(photon_swap_buffers(framebuffer_map->get_handle()) < 0)
    throw std::runtime_error("Display::swap: Failed to swap"
                             "framebuffers\n");
}

void Display::Clear(uint32_t color)
{
    auto fb = framebuffer_map->mapping;
    auto width = framebuffer_map->get_width();
    auto height = framebuffer_map->get_height();
    auto bpp = framebuffer_map->get_bpp();

    display_fill_rect(fb, 0, 0, width, height, color);
    swap();
}

void Display::copy(std::shared_ptr<Buffer> buffer, unsigned int x, unsigned int y)
{
    void *buffer_raw = buffer->mapping;
    char *fb_mapping = (char *) framebuffer_map->mapping;

    auto stride = framebuffer_map->get_stride();
    auto bytespp = framebuffer_map->get_bpp() / 8;
    auto buffer_height = buffer->get_height();
    auto buffer_width = buffer->get_width();

    fb_mapping += (y * stride) + x * bytespp;
    volatile uint32_t *fb = (volatile uint32_t *) fb_mapping;
    volatile uint32_t *backbuffer = (volatile uint32_t *) buffer_raw;

    for (size_t i = 0; i < buffer_height; i++)
    {
        for (size_t j = 0; j < buffer_width; j++)
            fb[j] = *backbuffer++;
        fb = (volatile uint32_t *) ((char *) fb + stride);
    }
}
