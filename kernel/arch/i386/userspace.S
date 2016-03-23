; Copyright 2016 Pedro Falcato
;
;Licensed under the Apache License, Version 2.0 (the "License");
;you may not use this file except in compliance with the License.
;You may obtain a copy of the License at
;
;http ://www.apache.org/licenses/LICENSE-2.0
;
;Unless required by applicable law or agreed to in writing, software
;distributed under the License is distributed on an "AS IS" BASIS,
;WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;See the License for the specific language governing permissions and
;limitations under the License.
;
;**************************************************************************
;
;
;* File: userspace.S
;
;* Description: Contains the x86 procedure to jump to userspace
;
;* Date: 30/1/2016
;
;
;**************************************************************************
section .data
	msg db 'SYSCALL WORKS',0
section .text
test:
	jmp .lp
.lp:
	jmp .lp
global jump_userspace
jump_userspace:
	mov ax,0x23
	mov ds,ax
	mov es,ax
	mov fs,ax
	mov gs,ax
	mov eax,esp
	push 0x23
	push eax
	pushf
	push 0x1B
	push test
	iret
