/*
* Copyright (c) 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <drm/drm.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

class RenderDevice
{
	private:
		struct drm_fb *drm_framebuffer;
		volatile unsigned char *backbuffer;
		volatile unsigned int *buffer;
	public:
		RenderDevice();
		~RenderDevice(){}
		void DrawLine(int fromx, int fromy, int tox, int toy, unsigned int color);
		inline void PutPixel(int x, int y, unsigned int color)
		{
			unsigned long index = y * (drm_framebuffer->pitch / drm_framebuffer->bpp) + x;
			buffer[index] = color;
		}
		void Draw();
};
RenderDevice::RenderDevice()
{
	struct drm_info *info;
	if(drm_initialize(&info) < 0)
		errx(1, "Failed to initialize drm!\n");
	drm_framebuffer = drm_map_fb();
	if(!drm_framebuffer)
		errx(1, "Failed to map the framebuffer!\n");

	/* Get the backbuffer */
	backbuffer = drm_framebuffer->framebuffer;

	/* Allocate a double buffer */
	buffer = (volatile unsigned int*) malloc(drm_framebuffer->width * drm_framebuffer->height * drm_framebuffer->bpp);
	if(!buffer)
		errx(1, "Failed to map the double buffer!\n");
	memset((void*) buffer, 0, drm_framebuffer->width * drm_framebuffer->height * drm_framebuffer->bpp);
}
void RenderDevice::DrawLine(int fromx, int fromy, int tox, int toy, unsigned int color)
{
	for(float t = 0.; t < 1; t += .01)
	{
		int x = fromx * (1. - t) + tox * t;
		int y = fromy * (1. - t) + toy * t;
		PutPixel(x, y, color);
	}
}
void RenderDevice::Draw()
{
	PutPixel(100, 10, 0xFFFF00);
	/* Sync the two buffers together */
	memcpy((void*) backbuffer, (void*) buffer, drm_framebuffer->width * drm_framebuffer->height * (drm_framebuffer->bpp / 8));

}
class Game
{
	private:
		RenderDevice dev;
	public:
		Game();
		~Game();
		int Run();
};
Game::Game() : dev()
{
	dev.DrawLine(500, 500, 500, 500-100, 0xFFFF00);
	dev.Draw();
	while(1);
	//printf("Hey!\n");
}
Game::~Game()
{

}
int Game::Run()
{

}
int main()
{
	Game game;
	return game.Run();
}
