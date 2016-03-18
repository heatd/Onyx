/* Copyright 2016 Pedro Falcato

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http ://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/* log.h: Kernel log */
#pragma once
#include <kernel/tty.h>
#include <stdio.h>
#include <drivers/vesa.h>
#include <string.h>
typedef struct interfaces
{
	const char* write_facility;
	const char* video_drivers;
	interfaces(const char* wrt_fac,const char* vid_drv)
	{
		write_facility = wrt_fac;
		video_drivers = vid_drv;
	}
}interfaces_t;
class Log
{
private:
	const char* write_facility;
	const char* video_drivers;
public:
	Log(const char* write_fac,const char* vid_drv);
	~Log();
	interfaces_t* GetInterfaces();
	void* GetTextFramebuffer();
	vid_mode_t* GetVidMode();
	Log& operator<<(int const& data)
	{
		printf("%d\n",data);
		return *this;
	}
	template <typename T>
	Log& operator<<(T* ptr)
	{
		printf("%p\n",ptr);
		return *this;
	}
	Log& operator<<(const char* data)
	{
		if(strcmp((char*)data,"\x1b[32m") == 0)
		{
			TTY::SetColor(0x00FF00);
			return *this;
		}
		else if(strcmp((char*)data,"\x1b[31m") == 0)
		{
			TTY::SetColor(0xFF0000);
			return *this;
		}
		else if(strcmp((char*)data,"\x1b[0m") == 0)
		{
			TTY::SetColor(0xC0C0C0);
			return *this;
		}

		printf("%s",data);
		return *this;
	}
	// The log is uncopyable, as it should be a unique object
	 Log( const Log& other ) = delete;
	 Log& operator=( const Log& ) = delete;
};
