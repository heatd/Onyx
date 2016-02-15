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
#include <kernel/tty.h>
#include <kernel/vga.h>
#include <kernel/fd.h>
ssize_t sys_write(int fd,const void* buf, size_t count)
{
	char* buffer = (char*)buf;
	if(fd == 1) //STDOUT
	{
		TTY::Write(buffer,count);
	}else if (fd == 2)
	{
		TTY::SetColor(make_color(COLOR_RED,COLOR_BLACK));
		
	}
	//Implement writing to files,when we support ATA/PATA/SATA/AHCI
}
ssize_t sys_read(int fd,const void* buf,size_t count)
{
	(void)fd;
	(void)buf;
	(void)count;
	//TODO
	return NULL;
}