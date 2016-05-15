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
#include <drivers/serial.h>
#include <string.h>
#include <stdio.h>
#include <kernel/panic.h>
uint32_t serial_write_nd(fs_node_t *node, uint32_t offset, uint32_t size, void *buffer)
{
	(void) node;
	(void) offset;
	char *prnt = buffer;
	for( size_t i = 0; i < size; i++ ) {
		serial_write(*prnt);
		prnt++;
	}
	return size;
}
int serial_recieved()
{
	return inb(PORT + 5) & 1;
}
int is_transmit_empty()
{
	return inb(PORT + 5) & 0x20;
}
void serial_init()
{
	outb(PORT + 1, 0x00);
	outb(PORT + 3, 0x80);
	outb(PORT + 0, 0x03);
	outb(PORT + 1, 0x00);
	outb(PORT + 3, 0x03);
	outb(PORT + 2, 0xC7);
	outb(PORT + 4, 0x0B);
	/*fs_node_t *dev = open_fs(NULL,0,0, "/dev/serial0");
	if(!dev)
		panic("Could allocate a node for serial0");
	dev->flags = FS_CHARDEVICE;
	dev->write = &serial_write_nd;*/
}
char serial_read()
{
	while(serial_recieved() == 0);

	return inb(PORT);
}
void serial_write(char c)
{
	while(is_transmit_empty() == 0);

	outb(PORT,c);

}
void serial_write_string(const char* str)
{
	size_t size = strlen(str);
	char *prnt = (char *) str;
	for(size_t sz = 0; sz < size; sz++)
	{
		while(is_transmit_empty() == 0);

		outb(PORT,*prnt);
		prnt++;
	}
}
