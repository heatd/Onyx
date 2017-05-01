/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Onyx, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <kernel/vfs.h>
#include <kernel/dev.h>
#include <kernel/vmm.h>
#include <kernel/module.h>
#include <kernel/log.h>
#include <kernel/video.h>

#include <drivers/softwarefb.h>

#include <drm-kernel.h>

#include <drm/drm.h>

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_GPL2);
MODULE_INSERT_VERSION();

#define MPRINTF(...) printf("drm: "__VA_ARGS__)

static vfsnode_t *drm_node = NULL;

#define VALIDATE_VALIST(args) \
if(!vmm_is_mapped(args)) \
	return -EFAULT; \

extern void *phys_fb;
unsigned int drm_ioctl(int request, va_list args, vfsnode_t *self)
{
	switch(request)
	{
		case DRM_REQUEST_DRMINFO:
		{
			VALIDATE_VALIST(args);
			struct drm_info *info = va_arg(args, struct drm_info *);

			if(vmm_check_pointer(info, sizeof(struct drm_info)) < 0)
				return -EFAULT;
			strcpy(info->drm_version, DRM_VERSION_STRING);
			/* TODO: Actually detect this in the future */
			strcpy(info->video_driver, DRM_SOFTWARE_DRIVER_STRING);
			strcpy(info->card, DRM_SOFTWARE_CARD_STRING);

			break;
		}
		case DRM_REQUEST_GET_FB:
		{
			VALIDATE_VALIST(args);
			struct drm_fb *out = va_arg(args, struct drm_fb *);

			if(vmm_check_pointer(out, sizeof(struct drm_fb)) < 0)
				return -EFAULT;
			
			/* Get the current video mode */
			struct video_mode *v = video_get_videomode(video_get_main_adapter());
			/* Map the framebuffer */
			/* TODO: Do this better, without hardcoded variables */
			void *ptr = dma_map_range(phys_fb, v->width * v->height * v->bpp, VM_USER | VM_WRITE);
			if(!ptr)
				return -ENOMEM;

			out->framebuffer = ptr;
			out->width = v->width;
			out->height = v->height;
			out->bpp = v->bpp;
			out->pitch = v->pitch;

			break;
		}
	}
	return 0;
}
int module_init()
{
	MPRINTF("initializing DRM\n");

	drm_node = creat_vfs(slashdev, "/dev/drm", 0666);
	if(!drm_node)
	{
		MPRINTF("error while creating the 'drm' device node: %s\n", strerror(errno));
		return 1;
	}
	struct minor_device *min = dev_register(0, 0);
	if(!min)
	{
		FATAL("drm", "could not create a device ID for /dev/drm: %s\n", strerror(errno));
		return 1;
	}
	min->fops = malloc(sizeof(struct file_ops));
	if(!min->fops)
	{
		dev_unregister(min->majorminor);
		FATAL("drm", "could not create a file operation table for /dev/drm: %s\n", strerror(errno));
		return 1;
	}
	memset(min->fops, 0, sizeof(struct file_ops));
	min->fops->ioctl = drm_ioctl;
	drm_node->dev = min->majorminor;

	MPRINTF("created /dev/drm\n");

	return 0;
}
int module_fini()
{
	MPRINTF("de-initializing DRM\n");
	free(drm_node);
	return 0;
}