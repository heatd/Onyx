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
int serial_recieved()
{
	return inb(PORT + 5) & 1;	
}
int is_transmit_empty()
{
	return inb(PORT + 5) & 0x20;
}
namespace Serial
{
	void Init()
	{
		outb(PORT + 1, 0x00);    // Disable all interrupts
		outb(PORT + 3, 0x80);    // Enable DLAB (set baud rate divisor)
		outb(PORT + 0, 0x03);    // Set divisor to 3 (lo byte) 38400 baud
		outb(PORT + 1, 0x00);    //                  (hi byte)
		outb(PORT + 3, 0x03);    // 8 bits, no parity, one stop bit
		outb(PORT + 2, 0xC7);    // Enable FIFO, clear them, with 14-byte 	threshold
		outb(PORT + 4, 0x0B);    // IRQs enabled, RTS/DSR set
	}
	char Read()
	{
		while(serial_recieved() == 0);
		
		return inb(PORT);
	}
	void Write(char c)
	{
		while(is_transmit_empty() == 0);
		
		outb(PORT,c);
		
	}
	void WriteString(const char* str)
	{
		size_t size = strlen(str);
		for(size_t sz = 0; sz < size; sz++)
		{
			Write(str[sz]);
		}
	}
	
	
}
