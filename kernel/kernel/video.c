/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <stdatomic.h>

#include <onyx/video.h>

static struct video_device *main_adapter = NULL;

void *video_get_fb(struct video_device *dev)
{
	if(dev->status == VIDEO_STATUS_REMOVED)
		return errno = ENODEV, NULL;
	if(dev->ops->get_fb)
		return dev->ops->get_fb(dev);
	return NULL;
}

void *video_create_fb(struct video_device *dev)
{
	if(dev->status == VIDEO_STATUS_REMOVED)
		return errno = ENODEV, NULL;
	if(dev->ops->create_fb)
		return dev->ops->create_fb(dev);
	/* TODO: Fallback on softfb */
	return errno = ENOSYS, NULL;
}

int video_draw_cursor(int x, int y, int fgcolor, int bgcolor, void *fb, struct video_device *dev)
{
	if(dev->status == VIDEO_STATUS_REMOVED)
		return errno = ENODEV, -1;
	if(dev->ops->draw_cursor)
		return (void) dev->ops->draw_cursor(x, y, fgcolor, bgcolor, fb), 0;
	return 0;
}

int video_draw_char(unsigned char c, int x, int y, int fgcolor, int bgcolor, void* fb, struct video_device *dev)
{
	if(dev->status == VIDEO_STATUS_REMOVED)
		return errno = ENODEV, -1;
	if(dev->ops->draw_char)
		return (void) dev->ops->draw_char(c, x, y, fgcolor, bgcolor, fb), 0;
	return 0;
}

int video_modeset(unsigned int width, unsigned int height, unsigned int bpp, struct video_device *dev)
{
	if(dev->status == VIDEO_STATUS_REMOVED)
		return errno = ENODEV, -1;
	if(dev->ops->modeset)
		return dev->ops->modeset(width, height, bpp, dev);
	return 0;
}

struct video_mode *video_get_videomode(struct video_device *dev)
{
	if(dev->status == VIDEO_STATUS_REMOVED)
		return errno = ENODEV, NULL;
	if(dev->ops->get_videomode)
		return dev->ops->get_videomode(dev);
	return NULL;
}

int video_scroll(void *fb, struct video_device *dev)
{
	if(dev->status == VIDEO_STATUS_REMOVED)
		return errno = ENODEV, -1;
	if(dev->ops->scroll)
		return dev->ops->scroll(fb), 0;
	return 0;
}

void video_remove(struct video_device *dev)
{
	dev->status = VIDEO_STATUS_REMOVED;
}

void video_set_main_adapter(struct video_device *dev)
{
	if(main_adapter)
		video_remove(main_adapter);
	main_adapter = dev;
}

struct video_device *video_get_main_adapter(void)
{
	if(!main_adapter)
		return NULL;
	atomic_fetch_add(&main_adapter->refcount, 1);
	return main_adapter;
}
