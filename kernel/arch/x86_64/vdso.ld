/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
SECTIONS
{
	. = SIZEOF_HEADERS;

	.dynamic :
	{
		*(.dynamic)
	} : text : dynamic

	.text : ALIGN(0x1000)
	{
		*(.text*)
		*(.gnu.linkonce.t*)
	} : text

	.rodata : ALIGN(0x1000)
	{
		*(.rodata*)
		*(.gnu.linkonce.r*)
		*(.data)
		*(.gnu.linkonce.d*)
		*(COMMON)
		*(.bss)
		*(.gnu.linkonce.b*)
	} : text

	.eh_frame_hdr : ALIGN(0x1000)
	{
		*(.eh_frame_hdr*)
	} : eh_frame_hdr
}

PHDRS
{
	text			PT_LOAD		FLAGS(5) FILEHDR PHDRS; /* R-X */
	dynamic			PT_DYNAMIC	FLAGS(4);				/* R-- */
	eh_frame_hdr	PT_GNU_EH_FRAME;
}
