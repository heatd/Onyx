bits 64

section .vdso

global __vdso_start
global __vdso_end
global __vdso_size

align 0x1000
__vdso_start:	incbin "onyx-vdso.so.0"
align 0x1000
__vdso_end:
__vdso_size:	dd $ - __vdso_start
