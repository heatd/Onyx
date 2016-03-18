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
#include <kernel/log.h>

Log::Log(const char* write_fac,const char* vid_drv)
{
	// IDK what i should put in here honestly, maybe i will add a call to fopen() once i implement it
	write_facility = write_fac;
	video_drivers  = vid_drv;
}
Log::~Log()
{
}
interfaces_t* Log::GetInterfaces()
{
	return new interfaces_t(write_facility,video_drivers);
}
void* Log::GetTextFramebuffer()
{
	if(strcmp((char*)video_drivers,"vesa") == 0)
	{
		// If the video driver is vesa, get the framebuffer address directly from the drivers
		return Vesa::GetFramebufferAddr();
	}
	else
	{
		printf("Log::GetTextFramebuffer(): Error, Unknown video drivers\n");
		return nullptr;
	}
}
vid_mode_t* Log::GetVidMode()
{
	return Vesa::GetVideoMode();
}
