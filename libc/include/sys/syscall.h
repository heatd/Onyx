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
#ifndef SYSCALL_H
#define SYSCALL_H

#define TERMINAL_WRITE_SYSCALL 0
#define FORK_SYSCALL 1
#define EXIT_SYSCALL 2
#define EXEC_SYSCALL 3
#define ABORT_SYSCALL 4

#define SYSCALL(intno,ebxr,ecxr,edxr,edir) \
asm volatile("mov eax,intno"); \
asm volatile("mov ebx,ebxr"); \
asm volatile("mov ecx,ecxr"); \
asm volatile("mov edx,edxr"); \
asm volatile("mov edi,edir"); \
asm volatile("int 0x80"); \



#endif // SYSCALL_H
