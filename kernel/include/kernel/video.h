/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#ifndef _VIDEO_H
#define _VIDEO_H

#include <stdlib.h>
#include <stdint.h>

#define VIDEO_STATUS_INSERTED	0
#define VIDEO_STATUS_REMOVED	1

struct video_device;
struct video_mode
{
	unsigned long height, width, bpp, pitch;
};
struct video_ops
{
	void *(*get_fb)(struct video_device*);
	void *(*create_fb)(struct video_device*);
	void (*draw_cursor)(int x, int y, int fgcolor, int bgcolor, void *fb);
	void (*draw_char)(unsigned char c, int x, int y, int fgcolor, int bgcolor, void* fb);
	int (*modeset)(unsigned int width, unsigned int height, unsigned int bpp, struct video_device *);
	struct video_mode *(*get_videomode)(struct video_device *);
	void (*scroll)(void *fb);
};
struct video_device
{
	struct video_ops *ops;
	char *driver_string;
	char *card_string;
	int status;
	_Atomic unsigned long refcount;
};
#ifdef __cplusplus
extern "C" {
#endif
void *video_get_fb(struct video_device*);
void *video_create_fb(struct video_device*);
int video_draw_cursor(int x, int y, int fgcolor, int bgcolor, void *fb, struct video_device*);
int video_draw_char(unsigned char c, int x, int y, int fgcolor, int bgcolor, void* fb, struct video_device*);
int video_modeset(unsigned int width, unsigned int height, unsigned int bpp, struct video_device*);
struct video_mode *video_get_videomode(struct video_device*);
int video_scroll(void *fb, struct video_device *);
void video_set_main_adapter(struct video_device *dev);
struct video_device *video_get_main_adapter(void);
void video_remove(struct video_device *dev);
#ifdef __cplusplus
}
#endif
#endif
