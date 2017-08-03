/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <drm/drm.h>


int main(int argc, char **argv, char **envp)
{
	struct drm_info *info;
	printf("wserver - window server\n");
	if(drm_initialize(&info) < 0)
		err(1, "Could not initialize DRM\n");
	printf("Using %s, video driver %s card %s\n", info->drm_version, info->video_driver, info->card);
	struct drm_fb *fb = drm_map_fb();
	if(!fb)
		err(1, "Could not map the framebuffer\n");
	while(1);
	return 0;
}
