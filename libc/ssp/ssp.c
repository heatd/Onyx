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
 * File: ssp.c
 *
 * Description: Contains the implementation of the GCC stack protector functions
 *
 * Date: 2/2/2016
 *
 *
 **************************************************************************/

#include <stdint.h>
#include <stdlib.h>
#ifdef __is_spartix_kernel
#include <kernel/panic.h>
#endif

#if UINT32_MAX == UINTPTR_MAX
#define STACK_CHK_GUARD 0xdeadc0de
#else
#define STACK_CHK_GUARD 0xdeadd00ddeadc0de
#endif

uintptr_t __stack_chk_guard = STACK_CHK_GUARD;
__attribute__((noreturn))
void __stack_chk_fail()
{
#if __STDC_HOSTED__
	abort(); // abort() right away, its unsafe!
#elif __is_spartix_kernel
	panic("Stack smashing detected");
#endif
}
