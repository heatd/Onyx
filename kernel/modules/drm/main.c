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
	return -1; \

extern void *phys_fb;
unsigned int drm_ioctl(int request, va_list args, vfsnode_t *self)
{
	switch(request)
	{
		case DRM_REQUEST_DRMINFO:
		{
			VALIDATE_VALIST(args);
			struct drm_info *info = va_arg(args, struct drm_info *);

			if(!vmm_is_mapped(info))
				return -1;
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

			if(!vmm_is_mapped(out))
				return -1;
			
			/* Map the framebuffer */
			/* TODO: Do this better, without hardcoded variables */
			void *mapping_addr = vmm_allocate_virt_address(0, 1024, VMM_TYPE_REGULAR, VMM_USER | VMM_WRITE, 0);
			
			if(!mapping_addr)
				return errno = -ENOMEM, -1;
			
			uintptr_t temp = (uintptr_t) mapping_addr, temp2 = (uintptr_t) phys_fb; 
			for(int i = 0; i < 1024; i++)
			{
				paging_map_phys_to_virt(temp, temp2, VMM_WRITE | VMM_USER);
				temp += 4096;
				temp2 += 4096;
			}
			out->framebuffer = mapping_addr;
			/* Get the current video mode */
			videomode_t *v = softfb_getvideomode();
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