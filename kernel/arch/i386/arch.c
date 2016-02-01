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
/**************************************************************************
 * 
 * 
 * File: arch.c
 * 
 * Description: Contains architecture specific initialization functions
 * 
 * Date: 1/2/2016
 * 
 * 
 **************************************************************************/
#include <kernel/idt.h>
#include <kernel/gdt.h>
extern void init_sse();
void init_arch()
{
	init_sse();
	
	init_gdt();
	
	init_idt();
}