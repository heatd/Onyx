bits 64

section .vdso

global __vdso_start
global __vdso_end

align 0x1000
__vdso_start:	incbin "onyx-vdso.so.0"
align 0x1000
__vdso_end: dq 0xffffffffffffff00		; Somewhy, we need to pad this
