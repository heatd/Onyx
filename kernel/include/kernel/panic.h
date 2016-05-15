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
#ifndef _PANIC_H
#define _PANIC_H

#include <kernel/compiler.h>
#include <kernel/registers.h>
ARCH_SPECIFIC void halt();
ARCH_SPECIFIC void get_thread_ctx(registers_t* regs);
/* The functions halt and get_thread_ctx are architecture dependent, as they require manual assembly.
 * As so, its left for the architecture to implement these functions. The kernel exepcts them to be hooked.
 */
extern "C++"  __attribute__ ((noreturn,cold,noinline))
void panic(const char* msg);

#endif
