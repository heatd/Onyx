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
#ifndef _CPU_H
#define _CPU_H
#include <stdint.h>
typedef struct cpu {
	char manuid[13];
	char brandstr[48];
	uint32_t max_function;
	uint32_t stepping, family, model, extended_model, extended_family;
	/* Add more as needed*/
}cpu_t;
#define CPUID_MANUFACTURERID 		0
#define CPUID_MAXFUNCTIONSUPPORTED 	0x80000000
#define CPUID_BRAND0			0x80000002
#define CPUID_BRAND1 			0x80000003
#define CPUID_BRAND2 			0x80000004
#define CPUID_SIGN   			0x1
namespace CPU
{
	void Identify();
	void InitInterrupts();
}

#endif
