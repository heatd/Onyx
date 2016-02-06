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
void keyboard_handler()
{
	unsigned char status;
	unsigned char keycode;
	status = inb(PS2_STATUS);

	if(status & 0x01){
		keycode = inb(PS2_DATA);
		if(keycode < 0)
			return;
		send_event_to_kern(keycode);
	}
}
int init_keyboard()
{
	irq_t handler = &keyboard_handler;
	pic_unmask_irq(1);
	irq_install_handler(1,handler);
	return 0;
}

