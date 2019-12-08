/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Carbon, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _X86_SEGMENTS_H
#define _X86_SEGMENTS_H

#define KERNEL_CS	0x08
#define KERNEL_DS	0x10

#define USER32_CS_SEGMENT	0x18
#define USER32_DS_SEGMENT	0x20
#define USER_CS_SEGMENT		0x28
#define USER_DS_SEGMENT		0x30

#define X86_USER_MODE_FLAG	3

#define USER32_CS	(USER32_CS_SEGMENT | X86_USER_MODE_FLAG)
#define USER32_DS	(USER32_DS_SEGMENT | X86_USER_MODE_FLAG)
#define USER_CS		(USER_CS_SEGMENT | X86_USER_MODE_FLAG)
#define USER_DS		(USER_DS_SEGMENT | X86_USER_MODE_FLAG)

#define TSS_SEGMENT	0x38


#endif