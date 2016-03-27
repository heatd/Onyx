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
 * File: compiler.h
 *
 * Description: Contains GCC specific features and builtins
 *
 * Date: 1/2/2016
 *
 *
 **************************************************************************/
#ifndef COMPILER_H
#define COMPILER_H

#include <stdint.h>
#ifndef __GNUC__
#error "The OS needs to be compiled using GCC"
#endif /*__GNUC__ */
#ifndef __spartix__
#error "Spartix needs to be compiled using a Spartix Cross Compiler"
#endif /* __spartix__ */
#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)
#define TRAP() __builtin_trap()
#define PREFETCH(x,y,z) __builtin_prefetch(x,y,z)
#define ASSUME_ALIGNED(x,y) __builtin_assume_aligned(x,y)
#define ARCH_SPECIFIC extern

inline uint64_t rdtsc()
{
    	uint64_t ret;
    	__asm__ __volatile__ ( "rdtsc" : "=A"(ret) );
    	return ret;
}
#endif /* COMPILER_H */
