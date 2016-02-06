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
#include <kernel/irq.h>
#include <kernel/pic.h>
#include <kernel/portio.h>
#include <kernel/panic.h>
#include <stdio.h>
#include <drivers/ps2.h>
// This took a while to make... Some keys still remain, but I don't need them right now
unsigned char keys[]={0,'1','2','3','4','5','6','7','8','9','0','-','=','\b','\t',
'q','w','e','r','t','y','u','i','o','p','[',']','\n',0,'a','s','d','f','g','h',
'j','k','l',';','\'','`',0,'\\','z','x','c','v','b','n','m',',','.','/',0,'*',0,
' ',0,0,0,0,0,0,0,0,0,0,0,0,0,'7','8','9','-','4','5','6','+','1','2','3','0',
'.',0,0,0,0,0};
void keyboard_handler()
{
	unsigned char status;
	char keycode;
	char c;
	status = inb(PS2_STATUS);

	if(status & 0x01){
		keycode = inb(PS2_DATA);
		if(keycode < 0)
			return;
		c = keys[keycode-1];
		send_input_to_kern(c,keycode);
	}
}
int init_keyboard()
{
	outb(PS2_DATA,PS2_ECHO);
	io_wait();
	uint8_t status;
	
	status = inb(PS2_DATA);
	
	if(status!=PS2_ECHO)
		panic("No keyboard found!");
	irq_t handler = &keyboard_handler;
	pic_unmask_irq(1);
	irq_install_handler(1,handler);
	return 0;
}

