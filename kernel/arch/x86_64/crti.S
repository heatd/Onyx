;----------------------------------------------------------------------
; * Copyright (C) 2016 Pedro Falcato
; *
; * This file is part of Spartix, and is made available under
; * the terms of the GNU General Public License version 2.
; *
; * You can redistribute it and/or modify it under the terms of the GNU
; * General Public License version 2 as published by the Free Software
; * Foundation.
; *----------------------------------------------------------------------
section .init
global _init
_init:
	push rbp
	mov rbp, rsp
section .fini
global _fini
_fini:
	push rbp
	mov rbp, rsp
