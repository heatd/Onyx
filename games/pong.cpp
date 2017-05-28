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
#include <unistd.h>
#include <utility>
#include <signal.h>
#include <termios.h>

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
		void DrawLineSortix(long x0, long y0, long x1, long y1, unsigned int color);
		inline void PutPixel(int x, int y, unsigned int color)
		{
			unsigned long index = y * (drm_framebuffer->pitch / (drm_framebuffer->bpp / 8)) + x;
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
void RenderDevice::DrawLine(int x0, int y0, int x1, int y1, unsigned int color)
{ 
	bool steep = false;
	if(std::abs(x0 - x1) < std::abs(y0 - y1))
	{
		std::swap(x0, y0);
		std::swap(x1, y1);
		steep = true;
    	}
    	if(x0 > x1)
	{
		std::swap(x0, x1);
		std::swap(y0, y1);
    	}
	int dx = x1 - x0;
	int dy = y1 - y0;
	int derror2 = std::abs(dy) * 2;
	int error2 = 0;
	int y = y0;
	for (int x = x0; x <= x1; x++)
	{
		if(steep) 
			PutPixel(y, x, color); 
        	else 
			PutPixel(x, y, color);  
		error2 += derror2; 
       		if(error2 > dx)
		{ 
			y += (y1 > y0 ? 1 : -1); 
			error2 -= dx * 2; 
        	} 
	}
} 
void RenderDevice::Draw()
{
	/* Sync the two buffers together */
	memcpy((void*) backbuffer, (void*) buffer, drm_framebuffer->width * drm_framebuffer->height * (drm_framebuffer->bpp / 8));

}
/* Needs to be a global var since signal handlers need to access it */
static bool should_exit;
class Game
{
	private:
		RenderDevice dev;
		struct termios old_termios;
		unsigned long frame_count = 0;
	public:
		Game();
		~Game();
		int Run();
		int SetTerminalMode();
		int ResetTerminal();
		void PollKeypresses();
};
int Game::SetTerminalMode()
{
	printf("Setting terminal mode!\n");
	struct termios attr;
	tcgetattr(STDIN_FILENO, &attr);
	memcpy(&old_termios, &attr, sizeof(struct termios));
	attr.c_lflag &= ~(ICANON | ECHO); /* Clear ICANON and ECHO */
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &attr);
	printf("Done setting terminal mode!\n");
	return 0;
}
int Game::ResetTerminal()
{
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
	return 0;
}
void sigint_handler(int signal)
{
	printf("Signal %d\n", signal);
	should_exit = true;
}
Game::Game() : dev()
{
	should_exit = false;
	signal(SIGINT, sigint_handler);
	SetTerminalMode();
}
Game::~Game()
{
	ResetTerminal();
}
char Game::PollKeypresses()
{
	return 0;
}
int Game::Run()
{
	while(!should_exit)
	{
		Game::PollKeypresses();
		dev.DrawLine(13, 20, 80, 40, 0xFF0000);
		dev.DrawLine(20, 13, 40, 80, 0xFF0000);
		dev.DrawLine(80, 40, 13, 20, 0xFF0000);
		dev.Draw();
		++frame_count;
	}
	return 0;
}
int main()
{
	Game game;
	/* TODO: Exception info unwinding is causing an abort(), so we can't use exit() or return from main */
	_Exit(game.Run());
}
