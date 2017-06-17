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
#include <fcntl.h>
#include <termios.h>
#include <cmath>

#define PIXELS_PER_KEY		20
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
			unsigned long index = y * (drm_framebuffer->pitch / (drm_framebuffer->bpp / 8)) + x;
			buffer[index] = color;
		}
		void DrawRectangule(int x, int y, int width, int height, unsigned int color);
		void Draw();
		inline struct drm_fb *GetDrmFb()
		{
			return drm_framebuffer;
		}
};
class Vector2f
{
private:
public:
	Vector2f(float x, float y);
	Vector2f();
	float x;
	float y;
	Vector2f operator*(Vector2f& x)
	{
		Vector2f vec;
		vec.x = x.x * this->x;
		vec.y = x.y * this->y;
		return vec;
	}
	Vector2f operator+(Vector2f& x)
	{
		Vector2f vec;
		vec.x = x.x + this->x;
		vec.y = x.y + this->y;
		return vec;
	}
	bool operator==(Vector2f &v)
	{
		if(v.x != x)
			return false;
		if(v.y != y)
			return false;
		return true;
	}
};
Vector2f::Vector2f(float x, float y) : x(x), y(y)
{
}
Vector2f::Vector2f()
{
	x = 0;
	y = 0;
}
class Actor
{
protected:
	Vector2f pos;
	Vector2f vel;
	Vector2f size;
	Vector2f old;
	unsigned int color;
	RenderDevice *dev;
public:
	Actor(const Vector2f&, const Vector2f&, const Vector2f&, RenderDevice *dev, unsigned int color);
	void Render();
	Vector2f& GetVel();
	Vector2f& GetPos();
	void SetVel(Vector2f&);
	void SetPos(Vector2f&);
	void SetSize(Vector2f&);
	Vector2f& GetSize();
};
Actor::Actor(const Vector2f& pos, const Vector2f& vel, const Vector2f& size, RenderDevice *dev, unsigned int color)
{
	this->pos = pos;
	this->vel = vel;
	this->size = size;
	this->dev = dev;
	this->color = color;
}
Vector2f& Actor::GetVel()
{
	return vel;
}
Vector2f& Actor::GetPos()
{
	return pos;
}
void Actor::SetVel(Vector2f& vec)
{
	vel = vec;
}
void Actor::SetPos(Vector2f& vec)
{
	pos = vec;
}
void Actor::SetSize(Vector2f& vec)
{
	size = vec;
}
Vector2f& Actor::GetSize()
{
	return size;
}
void Actor::Render()
{
	if(old == pos)
		return;
	int x = (int) std::ceil(pos.x);
	int y = (int) std::ceil(pos.y);
	dev->DrawRectangule((int) std::ceil(old.x), (int) std::ceil(old.y), (int) size.x, (int) size.y, 0);	
	dev->DrawRectangule(x, y, (int) size.x, (int) size.y, color);
	old = pos;
}
class Player : public Actor
{
public:
	Player(int x, int y, int width, int height, RenderDevice *dev, unsigned int color);
};
Player::Player(int x, int y, int width, int height, RenderDevice *dev, unsigned int color) : 
	Actor(Vector2f((float) x, (float) y), Vector2f(0.0f, 0.0f), Vector2f((float) width, (float) height), dev, color)
{

}
class Ball : public Actor
{
public:
	Ball(int x, int y, int width, int height, RenderDevice *dev, unsigned int color);
	bool Think();
	void ColidesWithP1(Player *p);
	void ColidesWithP2(Player *p);
	void Colide();
};
Ball::Ball(int x, int y, int width, int height, RenderDevice *dev, unsigned int color) : 
	Actor(Vector2f((float) x, (float) y), Vector2f(0.0f, 0.0f), Vector2f((float) width, (float) height), dev, color)
{
	vel.x = 2;
	vel.y = -2;
}
/* This function returns true on game over */
bool Ball::Think()
{
	Vector2f old = pos;
	pos.x = pos.x + vel.x;
	if(pos.x >= dev->GetDrmFb()->width || pos.x <= 0)
		return true;
	pos.y = pos.y + vel.y;
	if(pos.y <= 0 || pos.y >= dev->GetDrmFb()->height)
	{
		/* Inverse the speed */
		pos = old;
		vel.y = -vel.y;
		return false;
	}
	return false;
}
void Ball::Colide()
{
	vel.x = -vel.x;
	vel.y = -vel.y;
}
void Ball::ColidesWithP1(Player *p)
{
	Vector2f& ppos = p->GetPos();
	if(pos.x <= ppos.x && (pos.y > ppos.y && pos.y + size.y >= pos.y))
	{
		vel.x = -vel.x;
		vel.y = -vel.y;
		pos.x = ppos.x - size.x;
	}
}
void Ball::ColidesWithP2(Player *p)
{
	Vector2f& ppos = p->GetPos();
	if(pos.x >= ppos.x && (pos.y > ppos.y && pos.y + size.y >= pos.y))
	{
		vel.x = -vel.x;
		vel.y = -vel.y;
		pos.x = ppos.x + p->GetSize().x;
	}
}
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
void RenderDevice::DrawRectangule(int x, int y, int width, int height, unsigned int color)
{
	for(int i = 0; i < width; i++)
		DrawLine(x+i, y, x + i, y + height, color);
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
		Player *player1;
		Player *player2;
		Ball *ball;
	public:
		Game();
		~Game();
		int Run();
		int SetTerminalMode();
		int ResetTerminal();
		char PollKeypresses();
};
int Game::SetTerminalMode()
{
	struct termios attr;
	tcgetattr(STDIN_FILENO, &attr);
	memcpy(&old_termios, &attr, sizeof(struct termios));
	attr.c_lflag &= ~(ICANON | ECHO); /* Clear ICANON and ECHO */
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &attr);
	fcntl(STDIN_FILENO, F_SETFD, O_NONBLOCK);

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
	char c;
	if(read(STDIN_FILENO, &c, 1) == 0)
	{
		return 0;
	}
	switch(c)
	{
		case 'w':
		{
			Vector2f& vec = player1->GetPos();
			if(vec.y - PIXELS_PER_KEY < 0)
				break;
			vec.y -= PIXELS_PER_KEY;
			break;
		}
		case 's':
		{
			Vector2f& vec = player1->GetPos();
			if(vec.y + player1->GetSize().y + PIXELS_PER_KEY > dev.GetDrmFb()->height)	
				break;
			vec.y += PIXELS_PER_KEY;
			break;
		}
		case 'i':
		{
			Vector2f& vec = player2->GetPos();
			if(vec.y - PIXELS_PER_KEY < 0)
				break;
			vec.y -= PIXELS_PER_KEY;
			break;
		}
		case 'k':
		{
			Vector2f& vec = player2->GetPos();
			if(vec.y + player2->GetSize().y + PIXELS_PER_KEY > dev.GetDrmFb()->height)
				break;
			vec.y += PIXELS_PER_KEY;
			break;
		}
	}
	return 0;
}
int Game::Run()
{
again:
	player1 = new Player(60, 300, 10, 150, &dev, 0x808080);
	player2 = new Player(dev.GetDrmFb()->width - 60, 300, 10, 150, &dev, 0x808080);
	ball = new Ball(dev.GetDrmFb()->width / 2 - 10, dev.GetDrmFb()->height / 2 - 10, 10, 10, &dev, 0x808080);
	while(!should_exit)
	{
		PollKeypresses();
		player1->Render();
		player2->Render();
		if(ball->Think() == true)
		{
			delete player1;
			delete player2;
			delete ball;
			memset((void*) dev.GetDrmFb()->framebuffer, 0, dev.GetDrmFb()->width * dev.GetDrmFb()->height * (dev.GetDrmFb()->bpp / 8));
			goto again;
		}
		ball->ColidesWithP1(player1);
		ball->ColidesWithP2(player2);
		ball->Render();
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
