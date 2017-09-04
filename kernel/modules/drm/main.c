/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <onyx/vfs.h>
#include <onyx/dev.h>
#include <onyx/vmm.h>
#include <onyx/module.h>
#include <onyx/log.h>
#include <onyx/video.h>

#include <drivers/softwarefb.h>

#include <drm-kernel.h>

#include <drm/drm.h>

MODULE_AUTHOR("Pedro Falcato");
MODULE_LICENSE(MODULE_LICENSE_MIT);
MODULE_INSERT_VERSION();

#define MPRINTF(...) printf("drm: "__VA_ARGS__)

static struct inode *drm_node = NULL;

extern void *phys_fb;
unsigned int drm_ioctl(int request, void *args, struct inode *self)
{
	switch(request)
	{
		case DRM_REQUEST_DRMINFO:
		{
			struct drm_info *info = args;
			struct video_device *dev = video_get_main_adapter();
			
			struct drm_info kinfo = {0};
			strcpy(kinfo.drm_version, DRM_VERSION_STRING);
			strcpy(kinfo.video_driver, dev->driver_string);
			strcpy(kinfo.card, dev->card_string);

			if(copy_to_user(info, &kinfo, sizeof(struct drm_info)) < 0)
				return -EFAULT;
			break;
		}
		case DRM_REQUEST_GET_FB:
		{
			struct drm_fb *out = args;

			if(vmm_check_pointer(out, sizeof(struct drm_fb)) < 0)
				return -EFAULT;
			
			/* Get the current video mode */
			struct video_mode *v = video_get_videomode(video_get_main_adapter());
			if(!v)
				return -EIO;
			/* Map the framebuffer */
			/* TODO: Do this better, without hardcoded variables */
			void *ptr = dma_map_range(phys_fb, v->width * v->height * (v->bpp / 8), VM_USER | VM_WRITE);
			if(!ptr)
				return -ENOMEM;

			out->framebuffer = ptr;
			out->width = v->width;
			out->height = v->height;
			out->bpp = v->bpp;
			out->pitch = v->pitch;

			break;
		}
		case DRM_REQUEST_MODESET:
		{
			struct drm_modeset_args arg = {0};
			struct drm_modeset_args *uargs = args;
			if(copy_from_user(&arg, uargs, sizeof(struct drm_modeset_args)) < 0)
				return -EFAULT;
			struct video_device *device = video_get_main_adapter();
			if(!device)
				return errno = -ENODEV;
			return video_modeset(arg.width, arg.height, arg.bpp, device);
		}
	}
	return 0;
}
int module_init()
{
	MPRINTF("initializing DRM\n");

	drm_node = creat_vfs(slashdev, "drm", 0666);
	if(!drm_node)
	{
		MPRINTF("error while creating the 'drm' device node: %s\n", strerror(errno));
		return 1;
	}

	drm_node->fops.ioctl = drm_ioctl;
	drm_node->dev = 0;

	MPRINTF("created /dev/drm\n");

	return 0;
}
int module_fini()
{
	MPRINTF("de-initializing DRM\n");
	free(drm_node);
	return 0;
}
