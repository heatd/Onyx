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
section .text

%macro ISR_NOERRCODE 1
global isr%1
isr%1:
	cli
	push byte 0   ;push dummy err code
	push byte %1  ;push the interrupt number
	jmp isr_common ;Go to the handler
%endmacro


%macro ISR_ERRCODE 1
global isr%1
isr%1:
	cli
	push byte %1 ;push the interrupt number
	jmp isr_common ;Go to the handler
%endmacro

extern isr_handler
global isr_common
isr_common:
	
	;mov ax, ds               ; Lower 16-bits of eax = ds.
	;push eax                 ; save the data segment descriptor
	;mov ax, 10h		 ; load the kernel data segment descriptor
	;mov ds, ax
	;mov es, ax
	;mov fs, ax
	;mov gs, ax
	call isr_handler
	;pop eax        ; reload the original data segment descriptor
	;mov ds, ax
	;mov es, ax
	;mov fs, ax
	;mov gs, ax
	add esp,8
	iret
ISR_NOERRCODE 0
ISR_NOERRCODE 1
ISR_NOERRCODE 2
ISR_NOERRCODE 3
ISR_NOERRCODE 4
ISR_NOERRCODE 5
ISR_NOERRCODE 6
ISR_NOERRCODE 7
ISR_ERRCODE   8
ISR_NOERRCODE 9
ISR_ERRCODE   10
ISR_ERRCODE   11
ISR_ERRCODE   12
ISR_ERRCODE   13
ISR_ERRCODE   14
ISR_NOERRCODE 15
ISR_NOERRCODE 16
ISR_NOERRCODE 17
ISR_NOERRCODE 18
ISR_NOERRCODE 19
ISR_NOERRCODE 20
ISR_NOERRCODE 21
ISR_NOERRCODE 22
ISR_NOERRCODE 23
ISR_NOERRCODE 24
ISR_NOERRCODE 25
ISR_NOERRCODE 26
ISR_NOERRCODE 27
ISR_NOERRCODE 28
ISR_NOERRCODE 29
ISR_NOERRCODE 30
ISR_NOERRCODE 31
