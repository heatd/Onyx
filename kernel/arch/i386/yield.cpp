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
#include <kernel/yield.h>
#include <kernel/idt.h>
bool is_yielding;
/* This System Call is very simple, it yields the control to another task, by doing the IRQ0*/
//IS NOT WORKING
void sys_yield()
{
	is_yielding = true;
	irq0();
}
